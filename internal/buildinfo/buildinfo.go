// Package buildinfo carries build metadata injected at link time.
package buildinfo

// Version is the single source of truth for the module version. The build
// overrides it via:
//
//	-ldflags "-X github.com/chicohaager/zfw/internal/buildinfo.Version=x.y.z"
//
// The literal below is the fallback for `go run` / un-flagged builds.
var Version = "0.1.0-dev"
