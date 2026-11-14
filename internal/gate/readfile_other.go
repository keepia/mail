//go:build !unix

package gate

import "errors"

// readBounded needs O_NOFOLLOW and O_NONBLOCK; the gate runs on Linux.
func readBounded(string, int64) ([]byte, error) {
	return nil, errors.New("the gate's safe file read needs a Unix system")
}
