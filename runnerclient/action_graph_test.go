package runnerclient

import (
	"fmt"
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

func TestActionLookupDereferenceAndTargetAggregateBounds(t *testing.T) {
	for _, count := range []int{40, 41} {
		nodes := []ActionNode{{Path: "dir", Kind: "directory"}}
		for n := 0; n < count; n++ {
			target := "dir"
			if n+1 < count {
				target = fmt.Sprint("l", n+1)
			}
			nodes = append(nodes, ActionNode{Path: fmt.Sprint("l", n), Kind: "symlink", Target: target})
		}
		g, err := NewActionGraph(nodes)
		if err != nil {
			t.Fatal(err)
		}
		_, err = g.Resolve("l0", true)
		if (err != nil) != (count == 41) {
			t.Fatalf("%d dereferences: %v", count, err)
		}
	}
	nodes := []ActionNode{}
	for n := 0; n < 257; n++ {
		nodes = append(nodes, ActionNode{Path: fmt.Sprint("l", n), Kind: "symlink", Target: strings.Repeat("x", 4096)})
	}
	if _, err := NewActionGraph(nodes); err == nil {
		t.Fatal("aggregate target bound not enforced")
	}
}

func TestActionDeliveredProjectionCannotHideAliasDepth(t *testing.T) {
	for _, target := range []string{"../../x", "file"} {
		nodes := []ActionNode{{Path: "real", Kind: "directory"}, {Path: "real/sub", Kind: "directory"}, {Path: "real/sub/file", Kind: "file"}, {Path: "x", Kind: "file"}, {Path: "alias", Kind: "symlink", Target: "real/sub"}, {Path: "real/sub/link", Kind: "symlink", Target: target}}
		g, err := NewActionGraph(nodes)
		if err != nil {
			t.Fatal(err)
		}
		a := ActionAssignment{OutputStyle: "paths", Outputs: []ActionOutput{{Path: "alias/link", Kind: "any"}}}
		_, err = g.Select(a)
		if (err != nil) != (target == "../../x") {
			t.Fatalf("projected %q: %v", target, err)
		}
		c := ActionCompletion{Symlinks: []ActionSymlink{{Path: "alias/link", Target: target}}, WorkspaceNodes: nodes}
		if err = ValidateActionProjection(a, c); (err != nil) != (target == "../../x") {
			t.Fatalf("publication projection %q: %v", target, err)
		}
	}
}

func TestActionMissingFinalOutputAndDanglingParentDiffer(t *testing.T) {
	g, err := NewActionGraph([]ActionNode{{Path: "alias", Kind: "symlink", Target: "absent"}})
	if err != nil {
		t.Fatal(err)
	}
	a := ActionAssignment{OutputStyle: "paths", Outputs: []ActionOutput{{Path: "missing", Kind: "any"}}}
	if selection, err := g.Select(a); err != nil || len(selection) != 0 {
		t.Fatalf("ordinary missing output: %+v %v", selection, err)
	}
	a.Outputs[0].Path = "alias"
	if selection, err := g.Select(a); err != nil || len(selection) != 1 {
		t.Fatalf("final dangling link: %+v %v", selection, err)
	}
	a.Outputs[0].Path = "alias/out"
	if _, err := g.Select(a); err == nil {
		t.Fatal("dangling output parent omitted silently")
	}
}
