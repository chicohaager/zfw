//go:build !linux

package conntrack

import (
	"context"
	"errors"
)

// ctnetlink is a Linux-only interface. ZFW only ever runs on ZimaOS, but
// `go vet ./...` and editor tooling on other platforms must still build.
func readNetlink(context.Context, int) ([]Entry, error) {
	return nil, errors.New("ctnetlink: not supported on this platform")
}
