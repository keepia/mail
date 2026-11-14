// Package gatebundle is the file format of a gate's TLS material (#96,
// CD34 and CD35): the directory holds bundle.pem (the gate's leaf and key,
// the anchors its listeners trust and their revocation lists) and
// generation (a decimal counter). serve writes the control gate's
// directory (internal/controlgate); N4's agent writes the store gates'
// in the same format.
//
// The contract is #45's (rules 2-4 of 6874447630): the writer writes the
// bundle first and generation last, each by write, fsync and rename, and
// always writes a generation strictly greater than the last one. A reader
// applies any valid generation that differs from the one it holds
// (CD-N3-3), and then reads the bundle with Read. Both files are read
// with O_NOFOLLOW|O_NONBLOCK, checked by fstat on the opened file, bounded
// in size, and never quoted in an error.
package gatebundle

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
)

// File names in a gate's directory.
const (
	BundleFile     = "bundle.pem"
	GenerationFile = "generation"
)

// Size bounds of the two files (C12, CD35).
const (
	maxBundle     = 64 << 10
	maxGeneration = 32
)

// ErrRefused is wrapped by every refusal of a file's type, size or
// content. Its errors name the file and the fault, never the content.
var ErrRefused = errors.New("gate material refused")

// generationPattern is CD35's form: 1-19 decimal digits without a leading
// zero (or 0), and at most one trailing newline.
var generationPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,18})\n?$`)

// ReadGeneration reads dir/generation (CD35, X108-4): opened with
// O_NOFOLLOW|O_NONBLOCK, so a symbolic link is refused and a FIFO cannot
// hang; fstat must show a regular file; at most 32 bytes; the content
// must match ^(0|[1-9][0-9]{0,18})\n?$. A missing file gives an error that
// wraps fs.ErrNotExist; any other refusal wraps ErrRefused.
func ReadGeneration(dir string) (uint64, error) {
	path := filepath.Join(dir, GenerationFile)
	b, err := readFile(path, maxGeneration)
	if err != nil {
		return 0, err
	}
	if !generationPattern.Match(b) {
		return 0, fmt.Errorf("%w: %s is not a decimal generation of 1 to 19 digits", ErrRefused, path)
	}
	n, err := strconv.ParseUint(string(b[:len(b)-trailingNewline(b)]), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %s is not a decimal generation of 1 to 19 digits", ErrRefused, path)
	}
	return n, nil
}

func trailingNewline(b []byte) int {
	if len(b) > 0 && b[len(b)-1] == '\n' {
		return 1
	}
	return 0
}

// readFile reads the regular file path, at most limit bytes, without
// following a link and without blocking on a FIFO. Type and size are
// checked on the opened file.
func readFile(path string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil, fmt.Errorf("%s: %w", path, fs.ErrNotExist)
		}
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%w: %s is a symbolic link", ErrRefused, path)
		}
		return nil, fmt.Errorf("%w: open %s: %w", ErrRefused, path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("%w: fstat %s: %w", ErrRefused, path, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrRefused, path)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", ErrRefused, path, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: %s is longer than %d bytes", ErrRefused, path, limit)
	}
	return b, nil
}
