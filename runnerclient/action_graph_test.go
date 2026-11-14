package runnerclient

import (
	"math"
	"strings"
	"testing"
)

func TestActionComponentResolution(t *testing.T) {
	nodes := []ActionNode{{Path: "dir", Kind: "directory"}, {Path: "dir/sub", Kind: "directory"}, {Path: "x", Kind: "file"}, {Path: "a", Kind: "symlink", Target: "dir/sub"}, {Path: "loop", Kind: "symlink", Target: "loop"}, {Path: "reuse", Kind: "symlink", Target: "dir"}, {Path: "missing", Kind: "symlink", Target: "absent/../x"}, {Path: "escape", Kind: "symlink", Target: "../x"}, {Path: "root", Kind: "symlink", Target: "."}}
	g, err := NewActionGraph(nodes)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		p, want      string
		missing, bad bool
	}{
		{"a/../../x", "x", false, false}, {"reuse/../reuse/sub", "dir/sub", false, false}, {"missing", "x", true, false}, {"root", "", false, false}, {"loop", "", false, true}, {"escape", "", false, true}, {"x/../dir", "", false, true},
	} {
		got, e := g.Resolve(tc.p, true)
		if (e != nil) != tc.bad || e == nil && (got.Path != tc.want || got.Missing != tc.missing) {
			t.Fatalf("%q: %+v %v", tc.p, got, e)
		}
	}
	for _, target := range []string{"", "/x", "a\\b", "a:b", "a\x00b", "a\tb"} {
		if ActionTarget(target) {
			t.Fatalf("accepted %q", target)
		}
	}
	if !ActionTarget("../a//./b") {
		t.Fatal("rejected opaque relative target")
	}
}

func TestActionInputsAliasesAndProjection(t *testing.T) {
	in := ActionInputs{Directories: []string{"real", "real/sub"}, Symlinks: []ActionSymlink{{Path: "alias", Target: "real"}}}
	a := ActionAssignment{WorkingDirectory: "alias", OutputStyle: "paths", Outputs: []ActionOutput{{Path: "sub/out", Kind: "any"}}}
	prepared, err := PrepareActionInputs(a, in)
	if err != nil {
		t.Fatal(err)
	}
	g, err := InputGraph(prepared)
	if err != nil {
		t.Fatal(err)
	}
	g.nodes["real/sub/out"] = ActionNode{Path: "real/sub/out", Kind: "symlink", Target: "../sub"}
	selected, err := g.Select(a)
	if err != nil || len(selected) != 1 || selected[0].Logical != "sub/out" || selected[0].Node.Path != "real/sub/out" {
		t.Fatalf("selection %+v %v", selected, err)
	}
	a.OutputStyle = "legacy"
	a.Outputs[0].Kind = "file"
	if _, err = g.Select(a); err == nil {
		t.Fatal("legacy type mismatch accepted")
	}
	a.Outputs[0].Kind = "directory"
	if _, err = g.Select(a); err != nil {
		t.Fatal(err)
	}
	a.WorkingDirectory = "absent"
	if _, err = PrepareActionInputs(a, in); err == nil {
		t.Fatal("missing cwd accepted")
	}
	in.Symlinks = append(in.Symlinks, ActionSymlink{Path: "real/sub/dangling", Target: "absent"})
	a.WorkingDirectory = ""
	a.Outputs = []ActionOutput{{Path: "real/sub/dangling/out", Kind: "directory"}}
	if _, err = PrepareActionInputs(a, in); err == nil {
		t.Fatal("dangling output parent accepted")
	}
}

func TestActionGraphBoundsAndPhysicalParents(t *testing.T) {
	for _, nodes := range [][]ActionNode{
		{{Path: "f", Kind: "file"}, {Path: "f/x", Kind: "file"}},
		{{Path: "l", Kind: "symlink", Target: "."}, {Path: "l/x", Kind: "file"}},
		{{Path: "x", Kind: "file"}, {Path: "x", Kind: "directory"}},
		{{Path: "absent/x", Kind: "file"}},
		{{Path: "l", Kind: "symlink", Target: strings.Repeat("x", 4097)}},
	} {
		if _, err := NewActionGraph(nodes); err == nil {
			t.Fatalf("accepted %+v", nodes)
		}
	}
	if _, ok := ActionMemory(math.MaxInt64, MaxWorkspaceBytes); ok {
		t.Fatal("wrapped reservation")
	}
	if got, ok := ActionMemory(64<<20, MaxWorkspaceBytes); !ok || got != 256<<20 {
		t.Fatal(got, ok)
	}
	if HasActionFeatures(nil) || HasActionFeatures(append(append([]string{}, ActionFeatures...), "unknown")) {
		t.Fatal("accepted missing/unknown feature")
	}
}
