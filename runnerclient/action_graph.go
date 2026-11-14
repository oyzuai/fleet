package runnerclient

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"path"
	"slices"
	"strings"
)

var ActionFeatures = []string{"contained-symlinks", "typed-output-declarations", "workspace-snapshot-graph", "bounded-workspace-tmpfs-holder"}

func HasActionFeatures(features []string) bool {
	if len(features) != len(ActionFeatures) {
		return false
	}
	seen := map[string]bool{}
	for _, f := range features {
		if !slices.Contains(ActionFeatures, f) || seen[f] {
			return false
		}
		seen[f] = true
	}
	return true
}

func ActionMemory(memory, workspace int64) (int64, bool) {
	if memory < 0 || workspace < 0 || memory > math.MaxInt64-workspace {
		return 0, false
	}
	total := memory + workspace
	if total > math.MaxInt64-ActionHolderMemory-ActionInodeMemory {
		return 0, false
	}
	return total + ActionHolderMemory + ActionInodeMemory, true
}

// HostResources adds bounded bootstrap and in-memory transfer/lifecycle space.
// Customer action memory is never reduced to make helper overhead fit.
func (a ActionAssignment) HostResources() (memory, cpus, pids int64, ok bool) {
	memory, ok = ActionMemory(a.MemoryBytes, a.WorkspaceBytes)
	const overhead int64 = 320 << 20
	if !ok || memory > math.MaxInt64-overhead || a.NanoCPUs > math.MaxInt64-ActionHolderCPUs || a.PidsLimit > math.MaxInt64-ActionHolderPids {
		return 0, 0, 0, false
	}
	return memory + overhead, a.NanoCPUs + ActionHolderCPUs, a.PidsLimit + ActionHolderPids, true
}

// ActionTarget is syntax only. Root containment needs a complete action graph.
func ActionTarget(target string) bool {
	if target == "" || len(target) > 4096 || strings.HasPrefix(target, "/") || strings.ContainsAny(target, "\\:") {
		return false
	}
	for _, c := range target {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}

type ActionGraph struct{ nodes map[string]ActionNode }
type ActionLookup struct {
	Path, Kind string
	Missing    bool
}

// NewActionGraph accepts only physical entries with real directory parents.
// Unselected link targets stay inert; Resolve validates each traversed target.
func NewActionGraph(nodes []ActionNode) (*ActionGraph, error) {
	if len(nodes) >= MaxActionEntries {
		return nil, errors.New("workspace entry limit exceeded")
	}
	g := &ActionGraph{nodes: map[string]ActionNode{"": {Kind: "directory"}}}
	targetBytes := 0
	for _, n := range nodes {
		if !ActionPath(n.Path) {
			return nil, errors.New("invalid workspace path")
		}
		if _, ok := g.nodes[n.Path]; ok {
			return nil, errors.New("duplicate workspace entry")
		}
		switch n.Kind {
		case "file", "directory":
			if n.Target != "" {
				return nil, errors.New("target on non-link")
			}
		case "symlink":
			if len(n.Target) == 0 || len(n.Target) > 4096 {
				return nil, errors.New("invalid link target size")
			}
			targetBytes += len(n.Target)
		default:
			return nil, errors.New("invalid workspace kind")
		}
		if targetBytes > 1<<20 {
			return nil, errors.New("workspace link target limit exceeded")
		}
		g.nodes[n.Path] = n
	}
	for p := range g.nodes {
		if p != "" {
			parent := path.Dir(p)
			if parent == "." {
				parent = ""
			}
			if g.nodes[parent].Kind != "directory" {
				return nil, errors.New("workspace parent is not a real directory")
			}
		}
	}
	return g, nil
}

func InputGraph(in ActionInputs) (*ActionGraph, error) {
	nodes := []ActionNode{}
	seen := map[string]bool{}
	for _, f := range in.Files {
		nodes = append(nodes, ActionNode{Path: f.Path, Kind: "file"})
		seen[f.Path] = true
	}
	for _, d := range in.Directories {
		nodes = append(nodes, ActionNode{Path: d, Kind: "directory"})
		seen[d] = true
	}
	for _, l := range in.Symlinks {
		nodes = append(nodes, ActionNode{Path: l.Path, Kind: "symlink", Target: l.Target})
		seen[l.Path] = true
	}
	for i := 0; i < len(nodes); i++ {
		for p := path.Dir(nodes[i].Path); p != "."; p = path.Dir(p) {
			if !seen[p] {
				seen[p] = true
				nodes = append(nodes, ActionNode{Path: p, Kind: "directory"})
				if len(nodes) >= MaxActionEntries {
					return nil, errors.New("implicit workspace entry limit exceeded")
				}
			}
		}
	}
	return NewActionGraph(nodes)
}

func (g *ActionGraph) Nodes() []ActionNode {
	out := make([]ActionNode, 0, len(g.nodes)-1)
	for p, n := range g.nodes {
		if p != "" {
			out = append(out, n)
		}
	}
	slices.SortFunc(out, func(a, b ActionNode) int { return strings.Compare(a.Path, b.Path) })
	return out
}

// Resolve expands raw target components before pending '..' components. End
// markers distinguish an active cycle from legitimate later reuse of a link.
func (g *ActionGraph) Resolve(p string, followFinal bool) (ActionLookup, error) {
	type component struct{ name, end string }
	pending := []component{}
	for _, s := range strings.Split(p, "/") {
		pending = append(pending, component{name: s})
	}
	stack := []string{}
	active := map[string]bool{}
	dangling := false
	derefs := 0
	for len(pending) > 0 {
		c := pending[0]
		pending = pending[1:]
		if c.end != "" {
			delete(active, c.end)
			continue
		}
		current := strings.Join(stack, "/")
		if n, ok := g.nodes[current]; ok && n.Kind != "directory" {
			return ActionLookup{}, errors.New("workspace traversal through file")
		}
		if c.name == "" || c.name == "." {
			continue
		}
		if c.name == ".." {
			if len(stack) == 0 {
				return ActionLookup{}, errors.New("workspace link escapes root")
			}
			stack = stack[:len(stack)-1]
			continue
		}
		candidate := c.name
		if current != "" {
			candidate = current + "/" + c.name
		}
		if !ActionPath(candidate) {
			return ActionLookup{}, errors.New("workspace lookup expansion exceeds path bounds")
		}
		n, exists := g.nodes[candidate]
		last := true
		for _, v := range pending {
			if v.end == "" {
				last = false
				break
			}
		}
		if exists && n.Kind == "symlink" && (followFinal || !last) {
			if !ActionTarget(n.Target) || active[candidate] || derefs >= 40 {
				return ActionLookup{}, errors.New("unsafe or cyclic workspace link")
			}
			derefs++
			active[candidate] = true
			expanded := []component{}
			for _, s := range strings.Split(n.Target, "/") {
				expanded = append(expanded, component{name: s})
			}
			expanded = append(expanded, component{end: candidate})
			pending = append(expanded, pending...)
			continue
		}
		if !exists {
			dangling = true
		}
		stack = append(stack, c.name)
	}
	resolved := strings.Join(stack, "/")
	n, exists := g.nodes[resolved]
	return ActionLookup{Path: resolved, Kind: n.Kind, Missing: dangling || !exists}, nil
}

// PrepareActionInputs resolves directory aliases and creates only real missing
// output parents. A missing working directory is never silently manufactured.
func PrepareActionInputs(a ActionAssignment, in ActionInputs) (ActionInputs, error) {
	if err := in.Validate(); err != nil {
		return in, err
	}
	g, err := InputGraph(in)
	if err != nil {
		return in, err
	}
	cwd, err := g.Resolve(a.WorkingDirectory, true)
	if err != nil || cwd.Missing || cwd.Kind != "directory" {
		return in, errors.New("working directory is not an existing directory")
	}
	for _, o := range a.Outputs {
		if o.Path == "" {
			continue
		}
		parent := path.Dir(o.Path)
		if parent == "." {
			continue
		}
		// Resolve each prefix separately so only the direct missing real component
		// is created. A dangling link parent cannot be repaired by directory creation.
		prefix := a.WorkingDirectory
		for _, part := range strings.Split(parent, "/") {
			parentLookup, e := g.Resolve(prefix, true)
			if e != nil || parentLookup.Missing || parentLookup.Kind != "directory" {
				return in, errors.New("dangling output parent")
			}
			physical := part
			if parentLookup.Path != "" {
				physical = parentLookup.Path + "/" + part
			}
			if _, ok := g.nodes[physical]; !ok {
				g.nodes[physical] = ActionNode{Path: physical, Kind: "directory"}
				if len(g.nodes) > MaxActionEntries {
					return in, errors.New("output parent expansion exceeds limit")
				}
			}
			if prefix != "" {
				prefix += "/"
			}
			prefix += part
			resolved, e := g.Resolve(prefix, true)
			if e != nil || resolved.Missing || resolved.Kind != "directory" {
				return in, errors.New("invalid output parent")
			}
		}
	}
	in.Directories = nil
	for _, n := range g.Nodes() {
		if n.Kind == "directory" {
			in.Directories = append(in.Directories, n.Path)
		}
	}
	return in, nil
}

type ActionSelection struct {
	Logical string
	Node    ActionNode
}

// Select preserves logical declaration names while selecting physical nodes.
func (g *ActionGraph) Select(a ActionAssignment) ([]ActionSelection, error) {
	cwd, err := g.Resolve(a.WorkingDirectory, true)
	if err != nil || cwd.Missing || cwd.Kind != "directory" {
		return nil, errors.New("invalid snapshot working directory")
	}
	selected := map[string]ActionNode{}
	for _, o := range a.Outputs {
		lookup := a.WorkingDirectory
		if o.Path != "" {
			parent := a.WorkingDirectory
			if dir := path.Dir(o.Path); dir != "." {
				if parent != "" {
					parent += "/"
				}
				parent += dir
			}
			resolved, e := g.Resolve(parent, true)
			if e != nil || resolved.Missing || resolved.Kind != "directory" {
				return nil, errors.New("missing or dangling output parent")
			}
		}
		if o.Path != "" {
			if lookup != "" {
				lookup += "/"
			}
			lookup += o.Path
		}
		found, e := g.Resolve(lookup, false)
		if e != nil {
			return nil, e
		}
		if found.Missing {
			continue
		}
		node := g.nodes[found.Path]
		target := found
		if node.Kind == "symlink" {
			target, e = g.Resolve(lookup, true)
			if e != nil {
				return nil, e
			}
		}
		if a.OutputStyle == "legacy" && (target.Missing || target.Kind != o.Kind) {
			return nil, errors.New("legacy output type mismatch")
		}
		add := func(logical string, n ActionNode) error {
			if old, ok := selected[logical]; ok && old != n {
				return errors.New("conflicting output projection")
			}
			if n.Kind == "symlink" {
				if _, e := g.Resolve(n.Path, true); e != nil {
					return e
				}
			}
			selected[logical] = n
			if len(selected) >= MaxActionEntries {
				return errors.New("logical output expansion exceeds limit")
			}
			return nil
		}
		if e = add(o.Path, node); e != nil {
			return nil, e
		}
		if node.Kind == "directory" {
			for p, n := range g.nodes {
				if p == found.Path || p == "" {
					continue
				}
				suffix := p
				if found.Path != "" {
					var ok bool
					suffix, ok = strings.CutPrefix(p, found.Path+"/")
					if !ok {
						continue
					}
				}
				logical := suffix
				if o.Path != "" {
					logical = o.Path + "/" + suffix
				}
				if e = add(logical, n); e != nil {
					return nil, e
				}
			}
		}
	}
	if err := g.validateDeliveredLinks(a, selected); err != nil {
		return nil, err
	}
	out := make([]ActionSelection, 0, len(selected))
	for p, n := range selected {
		out = append(out, ActionSelection{Logical: p, Node: n})
	}
	slices.SortFunc(out, func(a, b ActionSelection) int { return strings.Compare(a.Logical, b.Logical) })
	return out, nil
}

// Delivered parents are real directories, not the input aliases that selected
// them. Copy only bounded metadata into that namespace and preserve link text.
func (g *ActionGraph) validateDeliveredLinks(a ActionAssignment, selected map[string]ActionNode) error {
	hasLinks := false
	for _, n := range selected {
		if n.Kind == "symlink" {
			hasLinks = true
			break
		}
	}
	if !hasLinks {
		return nil
	}
	anchored := func(p string) string {
		if a.WorkingDirectory == "" {
			return p
		}
		if p == "" {
			return a.WorkingDirectory
		}
		return a.WorkingDirectory + "/" + p
	}
	parents := map[string]string{}
	for logical, n := range selected {
		p := anchored(logical)
		if n.Kind != "directory" {
			p = path.Dir(p)
			if p == "." {
				p = ""
			}
		}
		for p != "" {
			lookup, e := g.Resolve(p, true)
			if e != nil || lookup.Missing || lookup.Kind != "directory" {
				return errors.New("invalid delivered output parent")
			}
			parents[p] = lookup.Path
			p = path.Dir(p)
			if p == "." {
				p = ""
			}
		}
	}
	view := map[string]ActionNode{}
	origins := map[string]string{}
	for p, n := range g.nodes {
		view[p] = n
		origins[p] = p
	}
	ordered := make([]string, 0, len(parents))
	for p := range parents {
		ordered = append(ordered, p)
	}
	slices.SortFunc(ordered, func(a, b string) int {
		if depth := strings.Count(a, "/") - strings.Count(b, "/"); depth != 0 {
			return depth
		}
		return strings.Compare(a, b)
	})
	for _, logical := range ordered {
		physical := parents[logical]
		if physical == logical {
			continue
		}
		for p := range view {
			if p == logical || strings.HasPrefix(p, logical+"/") {
				delete(view, p)
				delete(origins, p)
			}
		}
		for p, n := range g.nodes {
			suffix := ""
			if p != physical {
				var ok bool
				suffix, ok = strings.CutPrefix(p, physical+"/")
				if physical == "" {
					suffix = p
					ok = true
				}
				if !ok {
					continue
				}
			}
			delivered := logical
			if suffix != "" {
				delivered += "/" + suffix
			}
			n.Path = delivered
			view[delivered] = n
			origins[delivered] = p
			if len(view) > MaxActionEntries {
				return errors.New("delivered metadata expansion exceeds limit")
			}
		}
	}
	for logical, n := range selected {
		p := anchored(logical)
		n.Path = p
		view[p] = n
		origins[p] = selected[logical].Path
	}
	nodes := make([]ActionNode, 0, len(view)-1)
	for p, n := range view {
		if p != "" {
			nodes = append(nodes, n)
		}
	}
	projected, err := NewActionGraph(nodes)
	if err != nil {
		return err
	}
	originalPath := func(p string) string {
		if source, ok := origins[p]; ok {
			return source
		}
		suffix := ""
		for p != "" {
			suffix = path.Base(p) + "/" + suffix
			p = path.Dir(p)
			if p == "." {
				p = ""
			}
			if source, ok := origins[p]; ok {
				return strings.TrimSuffix(strings.TrimPrefix(source+"/"+suffix, "/"), "/")
			}
		}
		return strings.TrimSuffix(suffix, "/")
	}
	for logical, n := range selected {
		if n.Kind == "symlink" {
			before, e := g.Resolve(n.Path, true)
			if e != nil {
				return e
			}
			after, e := projected.Resolve(anchored(logical), true)
			if e != nil || before.Path != originalPath(after.Path) || before.Missing != after.Missing {
				return errors.New("unsafe output link projection")
			}
		}
	}
	return nil
}

func (c ActionCompletion) Validate() error {
	if c.ErrorCode != "" {
		if len(c.Files)+len(c.Directories)+len(c.Symlinks)+len(c.WorkspaceNodes) > 0 {
			return errors.New("service failure contains outputs")
		}
		return nil
	}
	if len(c.Stdout)+len(c.Stderr) > MaxActionLogs {
		return errors.New("action log limit exceeded")
	}
	if _, err := NewActionGraph(c.WorkspaceNodes); err != nil {
		return err
	}
	seen := map[string]bool{}
	total := int64(0)
	targets := 0
	for _, f := range c.Files {
		sum := sha256.Sum256(f.Data)
		if !ActionPath(f.Path) || seen[f.Path] || f.Size != int64(len(f.Data)) || f.SHA256 != hex.EncodeToString(sum[:]) {
			return errors.New("invalid completion file")
		}
		seen[f.Path] = true
		total += f.Size
		if total > MaxActionBytes {
			return errors.New("completion byte limit exceeded")
		}
	}
	for _, d := range c.Directories {
		if (d != "" && !ActionPath(d)) || seen[d] {
			return errors.New("invalid completion directory")
		}
		seen[d] = true
	}
	for _, l := range c.Symlinks {
		if !ActionPath(l.Path) || !ActionTarget(l.Target) || seen[l.Path] {
			return errors.New("invalid completion link")
		}
		seen[l.Path] = true
		targets += len(l.Target)
	}
	if len(seen) >= MaxActionEntries || targets > 1<<20 {
		return errors.New("completion expansion limit exceeded")
	}
	return nil
}

func ValidateActionProjection(a ActionAssignment, c ActionCompletion) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.ErrorCode != "" {
		return nil
	}
	g, err := NewActionGraph(c.WorkspaceNodes)
	if err != nil {
		return err
	}
	selection, err := g.Select(a)
	if err != nil {
		return err
	}
	actual := map[string]ActionNode{}
	for _, f := range c.Files {
		actual[f.Path] = ActionNode{Kind: "file"}
	}
	for _, d := range c.Directories {
		actual[d] = ActionNode{Kind: "directory"}
	}
	for _, l := range c.Symlinks {
		actual[l.Path] = ActionNode{Kind: "symlink", Target: l.Target}
	}
	if len(actual) != len(selection) {
		return errors.New("incomplete output projection")
	}
	for _, s := range selection {
		n, ok := actual[s.Logical]
		if !ok || n.Kind != s.Node.Kind || n.Target != s.Node.Target {
			return errors.New("output differs from workspace projection")
		}
	}
	return nil
}
