// Package buildinfo resolves the source revision that produced the running
// binary so the public site can link the exact GitHub build it came from.
//
// The container build injects the exact commit through ldflags:
//
//	-ldflags "-X github.com/mutandae/mutandae/internal/buildinfo.Revision=${BUILD_SHA}"
//
// A plain `go run`/`go build` from a git checkout falls back to the VCS
// build information stamped by the toolchain, so the dashboard can always
// name the revision behind it. The value is a public commit id: it must
// never carry secrets or private build details.
package buildinfo

import "runtime/debug"

// Revision is overridden at container build time via -ldflags -X. It stays
// empty for local toolchain builds, where Current falls back to VCS stamps.
var Revision string

// Build describes the source revision behind the running binary.
type Build struct {
	// Revision is the full commit SHA, empty when unknown.
	Revision string
	// Dirty reports whether the working tree had uncommitted changes when
	// the binary was produced (only knowable for VCS-stamped builds).
	Dirty bool
}

// Current resolves the build revision: the ldflags-injected container value
// wins, then the toolchain's VCS stamps, then unknown.
func Current() Build {
	if Revision != "" {
		return Build{Revision: Revision}
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return Build{}
	}
	var build Build
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			build.Revision = setting.Value
		case "vcs.modified":
			build.Dirty = setting.Value == "true"
		}
	}
	return build
}

// Short returns the short revision used for display, or "unknown".
func (b Build) Short() string {
	if b.Revision == "" {
		return "unknown"
	}
	if len(b.Revision) < 7 {
		return b.Revision
	}
	return b.Revision[:7]
}

// URL returns the GitHub commit page for the revision, or "" when the
// revision is unknown.
func (b Build) URL() string {
	if b.Revision == "" {
		return ""
	}
	return "https://github.com/macel94/mutandae/commit/" + b.Revision
}
