//go:build !linux

package conntrack

import (
	"context"
	"errors"
)

// flushImpl is a Linux-only operation — ctnetlink CT_DELETE has no portable
// equivalent. ZFW only ever runs on ZimaOS (Linux); this stub keeps the
// package building on dev machines.
func flushImpl(context.Context, []PortKey) (int, error) {
	return 0, errors.New("ctnetlink flush: not supported on this platform")
}
