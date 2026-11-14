package gate

import "sync/atomic"

// connCap is the gate-wide cap of open connections (G13). A connection
// over the cap is accepted and closed at once, so its caller tempfails
// instead of queueing in the kernel's backlog.
type connCap struct {
	max  int64
	open atomic.Int64
}

func (c *connCap) acquire() bool {
	if c.open.Add(1) > c.max {
		c.open.Add(-1)
		return false
	}
	return true
}

func (c *connCap) release() { c.open.Add(-1) }
