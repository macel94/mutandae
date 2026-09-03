package buildinfo

import "testing"

func TestCurrentPrefersInjectedRevision(t *testing.T) {
	t.Cleanup(func() { Revision = "" })
	Revision = "abc123def4567890"
	build := Current()
	if build.Revision != "abc123def4567890" {
		t.Fatalf("Revision = %q, want injected value", build.Revision)
	}
	if build.Dirty {
		t.Fatal("injected revision must not report dirty")
	}
	if got := build.Short(); got != "abc123d" {
		t.Fatalf("Short() = %q, want abc123d", got)
	}
	if got := build.URL(); got != "https://github.com/macel94/mutandae/commit/abc123def4567890" {
		t.Fatalf("URL() = %q, want commit page", got)
	}
}

func TestShortAndURLWithoutRevision(t *testing.T) {
	// A toolchain build outside a VCS tree (go test from an extracted
	// archive) yields no revision; the display stays honest about it.
	if build := Current(); build.Revision == "" {
		if got := build.Short(); got != "unknown" {
			t.Fatalf("Short() = %q, want unknown", got)
		}
		if got := build.URL(); got != "" {
			t.Fatalf("URL() = %q, want empty", got)
		}
	}
}

func TestShortHandlesShortRevision(t *testing.T) {
	build := Build{Revision: "abc"}
	if got := build.Short(); got != "abc" {
		t.Fatalf("Short() = %q, want abc", got)
	}
}
