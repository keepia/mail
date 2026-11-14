//go:build !linux

package gate

import (
	"context"
	"errors"
)

// GenerationFileName is the file whose change means "read the material
// again" (#45 contract rule 2).
const GenerationFileName = "generation"

// watch needs inotify: the gate runs on Linux only. This stub keeps the
// package building elsewhere.
func (g *Gate) watch(context.Context) error {
	return errors.New("gate: the material watcher needs Linux (inotify)")
}
