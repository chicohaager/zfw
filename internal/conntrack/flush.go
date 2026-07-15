package conntrack

import "context"

// PortKey is a protocol ("tcp"/"udp") + destination port. Flush deletes every
// conntrack entry whose original tuple destination port matches one of these,
// so a connection to a port the operator just blocked stops immediately
// instead of surviving on the ESTABLISHED,RELATED fast-path.
type PortKey struct {
	Proto string
	Port  int
}

// Flush deletes the conntrack entries matching any of targets and returns how
// many it removed. It is a targeted teardown driven by rules.NewlyBlocked: the
// apply path passes only the (proto, port) pairs that just transitioned from
// allowed to denied, never the whole table. An empty targets list is a no-op.
//
// Deleting needs CAP_NET_ADMIN, same as reading; an entry that is already gone
// (ENOENT, e.g. it expired between the dump and the delete) is not an error.
// On platforms without ctnetlink this returns a "not supported" error.
func Flush(ctx context.Context, targets []PortKey) (int, error) {
	return flushImpl(ctx, targets)
}
