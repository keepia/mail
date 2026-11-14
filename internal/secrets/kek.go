// Package secrets holds Keepia Mail's control secrets (#96 part 1): the
// key-encryption key (KEK) in a file, the secrets sealed under it in
// PostgreSQL, and the bootstrap that creates them at the first start of
// serve and loads them at every later one.
package secrets

import (
	"bytes"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// KEKSize is the KEK's length in bytes.
const KEKSize = 32

// kekPrefix starts the KEK file's one line (CD1).
const kekPrefix = "keepia-kek-v1 "

// kekFileMax bounds what the loader reads of a KEK file.
const kekFileMax = 128

// HKDF labels of the KEK's uses (CD2, CD3). Every use gets its own;
// keepia-mail/v1/quarantine is reserved for §12's derived quarantine key.
const (
	labelKEKID   = "keepia-mail/v1/kek-id"
	labelSecrets = "keepia-mail/v1/secrets" //nolint:gosec // G101: an HKDF label, not a credential
)

// KEKID identifies a KEK without revealing it: 16 bytes of HKDF-SHA256 of
// the KEK with the label keepia-mail/v1/kek-id (CD3).
type KEKID [16]byte

// String is the id in hex.
func (id KEKID) String() string { return hex.EncodeToString(id[:]) }

// KEK is the key-encryption key.
type KEK struct {
	key [KEKSize]byte
	id  KEKID
}

// ID is the KEK's id.
func (k *KEK) ID() KEKID { return k.id }

func newKEK(key []byte) (*KEK, error) {
	if len(key) != KEKSize {
		return nil, fmt.Errorf("a KEK has %d bytes", KEKSize)
	}
	k := &KEK{}
	copy(k.key[:], key)
	id, err := hkdf.Key(sha256.New, key, nil, labelKEKID, len(k.id))
	if err != nil {
		return nil, err
	}
	copy(k.id[:], id)
	return k, nil
}

// GenerateKEK returns a new random KEK.
func GenerateKEK() (*KEK, error) {
	b := make([]byte, KEKSize)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return newKEK(b)
}

// fileContent is the KEK file's content: one line,
// keepia-kek-v1 <base64url without padding of the 32 bytes>.
func (k *KEK) fileContent() []byte {
	return []byte(kekPrefix + base64.RawURLEncoding.EncodeToString(k.key[:]) + "\n")
}

// ErrKEKFile is wrapped by every refusal of a KEK file's type, mode,
// owner or format. Its errors never quote the file's content.
var ErrKEKFile = errors.New("KEK file refused")

// kekFS is how the loader reaches the file system: the process's euid
// and, for tests, a hook between the open and the fstat.
type kekFS struct {
	// euid is the owner a KEK file must have.
	euid int
	// afterOpen, when set, runs right after the open (a test seam: the
	// loader must check the opened file, not the path).
	afterOpen func()
}

func defaultFS() kekFS { return kekFS{euid: os.Geteuid()} }

// load reads the KEK file at path (CD1, C1). It is opened with O_NOFOLLOW
// and O_NONBLOCK, so a symbolic link is refused and a FIFO cannot hang.
// The type, mode and owner are checked by fstat on the opened file, never
// on the path: it must be a regular file with no group or other
// permission bits, owned by the process's euid. At most 128 bytes are
// read, and the content must be exactly one KEK line. A missing file
// gives an error that wraps fs.ErrNotExist.
func (f kekFS) load(path string) (*KEK, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil, fmt.Errorf("%s: %w", path, os.ErrNotExist)
		}
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%w: %s is a symbolic link", ErrKEKFile, path)
		}
		return nil, fmt.Errorf("%w: open %s: %w", ErrKEKFile, path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { _ = file.Close() }()
	if f.afterOpen != nil {
		f.afterOpen()
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("%w: fstat %s: %w", ErrKEKFile, path, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrKEKFile, path)
	}
	if perm := st.Mode & 0o777; perm&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %04o; want no group or other permissions (0400)", ErrKEKFile, path, perm)
	}
	if int64(st.Uid) != int64(f.euid) {
		return nil, fmt.Errorf("%w: %s is owned by uid %d; want %d", ErrKEKFile, path, st.Uid, f.euid)
	}
	buf, err := io.ReadAll(io.LimitReader(file, kekFileMax+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", ErrKEKFile, path, err)
	}
	if len(buf) > kekFileMax {
		return nil, fmt.Errorf("%w: %s is longer than %d bytes", ErrKEKFile, path, kekFileMax)
	}
	return parseKEKFile(path, buf)
}

// parseKEKFile parses the KEK line. Its errors name only what is wrong.
func parseKEKFile(path string, buf []byte) (*KEK, error) {
	line, ok := bytes.CutPrefix(buf, []byte(kekPrefix))
	if !ok {
		return nil, fmt.Errorf("%w: %s does not start with %q", ErrKEKFile, path, kekPrefix[:len(kekPrefix)-1])
	}
	line, ok = bytes.CutSuffix(line, []byte("\n"))
	if !ok || bytes.ContainsAny(line, "\n\r") {
		return nil, fmt.Errorf("%w: %s is not one line ending in a newline", ErrKEKFile, path)
	}
	if len(line) != base64.RawURLEncoding.EncodedLen(KEKSize) {
		return nil, fmt.Errorf("%w: %s does not hold a %d-byte key", ErrKEKFile, path, KEKSize)
	}
	key := make([]byte, KEKSize)
	n, err := base64.RawURLEncoding.Strict().Decode(key, line)
	if err != nil || n != KEKSize {
		return nil, fmt.Errorf("%w: %s does not hold base64url without padding", ErrKEKFile, path)
	}
	return newKEK(key)
}

// writeNew writes k to path with O_CREAT|O_EXCL|O_NOFOLLOW and mode 0400,
// then syncs the file and its directory (CD7 step 1). It never replaces
// an existing file or follows a link: if path exists in any form, it
// fails.
func writeNew(path string, k *KEK) (err error) {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o400)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() {
		if cerr := file.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("close %s: %w", path, cerr)
		}
	}()
	// The umask may have taken bits off 0400, never added any; make it
	// exactly 0400.
	if err := file.Chmod(0o400); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if _, err := file.Write(k.fileContent()); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", path, err)
	}
	return syncDir(filepath.Dir(path))
}

// linkInPlace links newPath to path, then removes newPath and syncs the
// directory (CD7 step 3). link fails if path exists, so a KEK is never
// replaced.
func linkInPlace(newPath, path string) error {
	if err := os.Link(newPath, path); err != nil {
		return fmt.Errorf("link %s to %s: %w", newPath, path, err)
	}
	if err := os.Remove(newPath); err != nil {
		return fmt.Errorf("remove %s: %w", newPath, err)
	}
	return syncDir(filepath.Dir(path))
}

// removeStray removes a leftover kek.new, without following a link, and
// syncs the directory.
func removeStray(newPath string) error {
	if err := syscall.Unlink(newPath); err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("remove %s: %w", newPath, err)
	}
	return syncDir(filepath.Dir(newPath))
}

// syncDir fsyncs the directory dir, so a create, link or remove in it is
// durable.
func syncDir(dir string) error {
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open the directory %s: %w", dir, err)
	}
	d := os.NewFile(uintptr(fd), dir)
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync the directory %s: %w", dir, err)
	}
	return nil
}

// exists tells whether path exists in any form (lstat): a file, a link,
// a FIFO or a directory.
func exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}
