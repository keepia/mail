//go:build unix

package gate

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// readBounded reads the regular file path safely (C12's rules, G8): it
// never follows a symlink (O_NOFOLLOW), never blocks on a FIFO or device
// (O_NONBLOCK, then fstat must show a regular file), and reads at most
// limit bytes. A missing file wraps fs.ErrNotExist. No error quotes the
// file.
func readBounded(path string, limit int64) ([]byte, error) {
	name := filepath.Base(path)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0) // #nosec G304 -- a file in the gate's own material directory (--dir)
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil, fmt.Errorf("%s: %w", name, fs.ErrNotExist)
		case errors.Is(err, syscall.ELOOP):
			return nil, fmt.Errorf("%s: refused: a symlink", name)
		}
		return nil, fmt.Errorf("%s: refused: unreadable", name)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s: refused: unreadable", name)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: refused: not a regular file (%s)", name, st.Mode().Type())
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("%s: refused: more than %d bytes", name, limit)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: refused: unreadable", name)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: refused: more than %d bytes", name, limit)
	}
	return b, nil
}
