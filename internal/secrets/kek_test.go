package secrets

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/keepia/mail/internal/testwait"
)

// writeFile writes content to path with mode (exactly, despite the
// umask).
func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func testKEK(t *testing.T) *KEK {
	t.Helper()
	k, err := GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// loadBounded runs load in a goroutine, so a hang (a FIFO opened without
// O_NONBLOCK) fails the test at testwait.Limit instead of hanging it.
func loadBounded(t *testing.T, f kekFS, path string) (*KEK, error) {
	t.Helper()
	type result struct {
		k   *KEK
		err error
	}
	done := make(chan result, 1)
	go func() {
		k, err := f.load(path)
		done <- result{k, err}
	}()
	select {
	case r := <-done:
		return r.k, r.err
	case <-time.After(testwait.Limit(t)):
		t.Fatalf("load of %s did not return", path)
		return nil, nil
	}
}

// A valid KEK file loads, with the id of its key.
func TestLoadKEK(t *testing.T) {
	dir := t.TempDir()
	k := testKEK(t)
	path := filepath.Join(dir, "kek")
	if err := writeNew(path, k); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o400 {
		t.Fatalf("written mode %v, %v", st.Mode(), err)
	}
	got, err := defaultFS().load(path)
	if err != nil || got.id != k.id || got.key != k.key {
		t.Fatalf("load: %v", err)
	}
	if _, err := defaultFS().load(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: %v, want ErrNotExist", err)
	}
}

// S6. The loader refuses every unsafe or malformed KEK file, and its error
// never contains the file's bytes.
func TestLoadKEKRefuses(t *testing.T) {
	dir := t.TempDir()
	good := string(testKEK(t).fileContent())
	key := strings.TrimSuffix(strings.TrimPrefix(good, kekPrefix), "\n")
	b64 := func(n int) string {
		k := make([]byte, n)
		for i := range k {
			k[i] = byte(i + 1)
		}
		return kekPrefix + base64.RawURLEncoding.EncodeToString(k) + "\n"
	}
	cases := map[string]func(path string){
		"symlink": func(p string) {
			target := filepath.Join(dir, "target")
			writeFile(t, target, good, 0o400)
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(p string) {
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"directory":      func(p string) { _ = os.Mkdir(p, 0o700) },
		"mode 0440":      func(p string) { writeFile(t, p, good, 0o440) },
		"mode 0404":      func(p string) { writeFile(t, p, good, 0o404) },
		"mode 0644":      func(p string) { writeFile(t, p, good, 0o644) },
		"wrong prefix":   func(p string) { writeFile(t, p, "keepia-kek-v2 "+key+"\n", 0o400) },
		"31 key bytes":   func(p string) { writeFile(t, p, b64(31), 0o400) },
		"33 key bytes":   func(p string) { writeFile(t, p, b64(33), 0o400) },
		"trailing data":  func(p string) { writeFile(t, p, good+"x", 0o400) },
		"no newline":     func(p string) { writeFile(t, p, strings.TrimSuffix(good, "\n"), 0o400) },
		"padding":        func(p string) { writeFile(t, p, kekPrefix+key+"=\n", 0o400) },
		"oversized":      func(p string) { writeFile(t, p, good+strings.Repeat("y", 200), 0o400) },
		"empty":          func(p string) { writeFile(t, p, "", 0o400) },
		"CRLF":           func(p string) { writeFile(t, p, strings.TrimSuffix(good, "\n")+"\r\n", 0o400) },
		"standard b64":   func(p string) { writeFile(t, p, kekPrefix+strings.Repeat("+", len(key))+"\n", 0o400) },
		"another owner":  func(p string) { writeFile(t, p, good, 0o400) },
		"leading spaces": func(p string) { writeFile(t, p, " "+good, 0o400) },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "kek")
			setup(path)
			f := defaultFS()
			if name == "another owner" {
				// Tests cannot chown: the expected owner moves instead.
				f.euid = os.Geteuid() + 1
			}
			_, err := loadBounded(t, f, path)
			if !errors.Is(err, ErrKEKFile) {
				t.Fatalf("%v, want ErrKEKFile", err)
			}
			if strings.Contains(err.Error(), key) || strings.Contains(err.Error(), key[:8]) {
				t.Errorf("the error quotes the file: %v", err)
			}
		})
	}
}

// S8. The loader checks the opened file, not the path: a 0644 file is
// opened, then a 0400 file is renamed over the path; the load still
// refuses.
func TestLoadKEKChecksTheOpenedFile(t *testing.T) {
	dir := t.TempDir()
	good := string(testKEK(t).fileContent())
	path := filepath.Join(dir, "kek")
	writeFile(t, path, good, 0o644)
	safe := filepath.Join(dir, "safe")
	writeFile(t, safe, good, 0o400)
	f := defaultFS()
	f.afterOpen = func() {
		if err := os.Rename(safe, path); err != nil {
			t.Error(err)
		}
	}
	if _, err := f.load(path); !errors.Is(err, ErrKEKFile) {
		t.Fatalf("a 0644 file swapped for a 0400 one after the open: %v, want ErrKEKFile", err)
	}
	// The path itself now holds the safe file, which loads.
	if _, err := defaultFS().load(path); err != nil {
		t.Fatalf("the swapped-in file: %v", err)
	}
}

// S7. Creating a KEK never replaces a file: writeNew refuses an existing
// path (also a link to elsewhere), and the link refuses an existing KEK;
// the original stays.
func TestCreateKEKNeverReplaces(t *testing.T) {
	dir := t.TempDir()
	orig, other := testKEK(t), testKEK(t)
	path := filepath.Join(dir, "kek")
	newPath := path + ".new"
	if err := writeNew(path, orig); err != nil {
		t.Fatal(err)
	}
	if err := writeNew(path, other); err == nil {
		t.Error("writeNew replaced an existing file")
	}
	target := filepath.Join(dir, "elsewhere")
	if err := os.Symlink(target, newPath); err != nil {
		t.Fatal(err)
	}
	if err := writeNew(newPath, other); err == nil {
		t.Error("writeNew followed a link")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the link's target was created: %v", err)
	}
	if err := removeStray(newPath); err != nil {
		t.Fatal(err)
	}
	if err := writeNew(newPath, other); err != nil {
		t.Fatal(err)
	}
	if err := linkInPlace(newPath, path); err == nil {
		t.Error("the link replaced an existing KEK")
	}
	got, err := defaultFS().load(path)
	if err != nil || got.id != orig.id {
		t.Fatalf("the original KEK changed: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(b, orig.fileContent()) {
		t.Errorf("the original file changed: %v", err)
	}
}
