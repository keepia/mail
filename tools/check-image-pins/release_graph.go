package main

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Rule 7, principle A (#77): every job's condition, under GitHub's
// evaluation rules, gives exactly the planned job set in each mode. #73,
// #75 and #77 were each found only in a real run; this file proves the
// conditions statically instead, from the `needs` and `if` of the parsed
// workflow (not from the policy's strings, so a wrong policy string cannot
// pass):
//
//   - Graph: each job's direct needs and its ancestors (the transitive
//     needs). A need that names no job and a cycle are findings.
//   - Form: a job whose ancestors include a mode-exclusive job (one that
//     runs in one mode only) has exactly the canonical explicit condition
//     (releaseExplicitCond): `!cancelled()`, its mode and one
//     `needs.<j>.result == 'success'` per direct need, in the policy's
//     `needs` order (E-3), because a bare `if` gets an implicit success()
//     over every ancestor, and a skipped ancestor makes it false. The form
//     rule holds the `if` of these jobs in place of P6's comparison, with
//     the same expected string, so the two never ask for different fixes.
//   - Grammar: the evaluator reads exactly one `${{ }}` around the whole
//     value (or none), `!`, `&&`, `||`, parentheses, `inputs.dry_run`,
//     `needs.<direct need>.result == 'success'` and success(), failure(),
//     cancelled() and always(). Anything else is a finding: a condition
//     the rule cannot evaluate is never accepted.
//   - Simulation: every job in topological order, in a dry and a real run,
//     every job that runs passing; the jobs that run must be exactly
//     releaseDryJobs and releaseRealJobs.
//   - Failure injection: in each mode, for each job that runs, that job
//     failing; exactly the planned set minus its descendants must start.
//
// GitHub's rules, as the model implements them (the plan of #77; measured
// on run 43420238830 and dry run 43419047428):
//
//  1. A job `if` without a status function gets an implicit success().
//  2. At job level, success() is true only if every ancestor succeeded (a
//     skipped one makes it false); failure() is true if any ancestor
//     failed.
//  3. A job whose `if` is false is skipped; a skipped job reports success,
//     so a run's conclusion proves nothing about which jobs ran.
//  4. With always() or !cancelled() no implicit success() is added; the
//     job's own terms decide.
//  5. needs.<j>.result exists only for direct needs.

// The planned job sets of the two modes (#77; B adds push-arm64).
var (
	releaseRealJobs = []string{"version", "build", "push", "push-arm64", "index", "bundle", "attest", "attest-assets", "release", "latest"}
	releaseDryJobs  = []string{"version", "build", "push-rehearsal", "bundle"}
)

// The modes a job runs in, from the planned sets.
const (
	modeBoth = "both"
	modeReal = "real"
	modeDry  = "dry"
)

// releaseJobMode is the mode a job runs in; "" for a job in neither set.
func releaseJobMode(job string) string {
	r, d := slices.Contains(releaseRealJobs, job), slices.Contains(releaseDryJobs, job)
	switch {
	case r && d:
		return modeBoth
	case r:
		return modeReal
	case d:
		return modeDry
	}
	return ""
}

// modeExclusive reports whether a job runs in one mode only.
func modeExclusive(job string) bool {
	m := releaseJobMode(job)
	return m == modeReal || m == modeDry
}

// releaseAncestors returns a job's transitive needs (it terminates on a
// cycle; the cycle itself is reported by releaseGraphProblems).
func releaseAncestors(needs map[string][]string, job string) map[string]bool {
	out := map[string]bool{}
	stack := slices.Clone(needs[job])
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if out[n] {
			continue
		}
		out[n] = true
		stack = append(stack, needs[n]...)
	}
	return out
}

// exclusiveAncestor returns the first mode-exclusive ancestor of a job in
// order (the policy's job order), or "".
func exclusiveAncestor(needs map[string][]string, job string, order []string) string {
	anc := releaseAncestors(needs, job)
	for _, n := range order {
		if anc[n] && modeExclusive(n) {
			return n
		}
	}
	return ""
}

// releaseExplicitCond is the canonical explicit condition of a job in
// mode (#77): for one mode, `!cancelled()`, the mode term and one result
// term per need; for both modes (bundle), the needs of both modes, then
// the dry-only and the real-only needs, each behind its mode term.
func releaseExplicitCond(mode string, needs []string) string {
	term := func(n string) string { return "needs." + n + ".result == 'success'" }
	parts := []string{"!cancelled()"}
	switch mode {
	case modeReal, modeDry:
		if mode == modeReal {
			parts = append(parts, "!inputs.dry_run")
		} else {
			parts = append(parts, "inputs.dry_run")
		}
		for _, n := range needs {
			parts = append(parts, term(n))
		}
	default:
		dryTerms, realTerms := []string{"inputs.dry_run"}, []string{"!inputs.dry_run"}
		for _, n := range needs {
			switch releaseJobMode(n) {
			case modeDry:
				dryTerms = append(dryTerms, term(n))
			case modeReal:
				realTerms = append(realTerms, term(n))
			default:
				parts = append(parts, term(n))
			}
		}
		parts = append(parts, "(("+strings.Join(dryTerms, " && ")+") || ("+strings.Join(realTerms, " && ")+"))")
	}
	return "${{ " + strings.Join(parts, " && ") + " }}"
}

// releaseCondFor is the policy's `if` of a job, generated from the
// policy's own needs and the planned sets: none or the bare mode term for
// a job without a mode-exclusive ancestor (version, build, push,
// push-rehearsal), else the explicit form. TestReleasePolicyConds pins
// the results literally.
func releaseCondFor(jobs map[string]releaseJob, job string) string {
	needs := map[string][]string{}
	for n, j := range jobs {
		needs[n] = j.needs
	}
	mode := releaseJobMode(job)
	if exclusiveAncestor(needs, job, releaseJobOrder) == "" {
		switch mode {
		case modeReal:
			return releaseRealIf
		case modeDry:
			return releaseDryIf
		}
		return ""
	}
	return releaseExplicitCond(mode, jobs[job].needs)
}

// withReleaseConds fills in the policy's conditions.
func withReleaseConds(jobs map[string]releaseJob) map[string]releaseJob {
	for n, j := range jobs {
		j.cond = releaseCondFor(jobs, n)
		jobs[n] = j
	}
	return jobs
}

// releaseGraph is the `needs` and `if` of release.yml's jobs as written.
type releaseGraph struct {
	order []string            // the jobs in file order
	needs map[string][]string // direct needs, as written
	cond  map[string]any      // the `if` value; absent for no if
	line  map[string]int
}

func readReleaseGraph(jobsNode *yaml.Node) releaseGraph {
	g := releaseGraph{needs: map[string][]string{}, cond: map[string]any{}, line: map[string]int{}}
	for i := 0; i+1 < len(jobsNode.Content); i += 2 {
		name, val := jobsNode.Content[i], jobsNode.Content[i+1]
		var job map[string]any
		if val.Decode(&job) != nil {
			continue
		}
		g.order = append(g.order, name.Value)
		g.line[name.Value] = name.Line
		switch n := job["needs"].(type) {
		case string:
			g.needs[name.Value] = []string{n}
		case []any:
			for _, e := range n {
				s, _ := e.(string)
				g.needs[name.Value] = append(g.needs[name.Value], s)
			}
		}
		if c, ok := job["if"]; ok {
			g.cond[name.Value] = c
		}
	}
	return g
}

// releaseGraphProblems reports needs that name no job, and a cycle.
func releaseGraphProblems(g releaseGraph, add func(int, string, ...any)) bool {
	bad := false
	for _, j := range g.order {
		for _, n := range g.needs[j] {
			if _, ok := g.line[n]; !ok {
				add(g.line[j], "job %s: needs %q, which is not a job of release.yml (#77)", j, n)
				bad = true
			}
		}
	}
	if cycle := releaseCycle(g); cycle != nil {
		add(g.line[cycle[0]], "release.yml: the needs form a cycle (%s), so no job of it can run (#77)", strings.Join(cycle, " -> "))
		bad = true
	}
	return bad
}

// releaseCycle returns one cycle of the needs, or nil.
func releaseCycle(g releaseGraph) []string {
	const (
		white = iota
		grey
		black
	)
	color := map[string]int{}
	var path []string
	var visit func(string) []string
	visit = func(j string) []string {
		color[j] = grey
		path = append(path, j)
		for _, n := range g.needs[j] {
			if _, ok := g.line[n]; !ok {
				continue
			}
			switch color[n] {
			case grey:
				i := slices.Index(path, n)
				return append(slices.Clone(path[i:]), n)
			case white:
				if c := visit(n); c != nil {
					return c
				}
			}
		}
		path = path[:len(path)-1]
		color[j] = black
		return nil
	}
	for _, j := range g.order {
		if color[j] == white {
			if c := visit(j); c != nil {
				return c
			}
		}
	}
	return nil
}

// releaseTopo returns the jobs with every job after its needs (the graph
// has no cycle and no unknown need).
func releaseTopo(g releaseGraph) []string {
	var out []string
	done := map[string]bool{}
	var visit func(string)
	visit = func(j string) {
		if done[j] {
			return
		}
		done[j] = true
		for _, n := range g.needs[j] {
			visit(n)
		}
		out = append(out, j)
	}
	for _, j := range g.order {
		visit(j)
	}
	return out
}

// condNode is a parsed condition: and, or, not, dry (inputs.dry_run),
// need (needs.<name>.result == 'success') or fn (a status function).
type condNode struct {
	op   string
	kids []*condNode
	name string
}

// releaseCond is a job's parsed `if`: nil root for no if.
type releaseCond struct {
	root   *condNode
	status bool // a status function occurs, so no implicit success()
}

var (
	condNeedsResult = regexp.MustCompile(`^needs\.([A-Za-z0-9_-]+)\.result$`)
	condStatusFns   = map[string]bool{"success": true, "failure": true, "cancelled": true, "always": true}
)

// stringCondError is a refused `if` that GitHub reads as a non-empty
// string: it is reported, and the simulation evaluates it as a condition
// that is always true (with the implicit success(), as any `if` without
// a status function), so its effect on the job sets shows too.
type stringCondError string

func (e stringCondError) Error() string { return string(e) }

// unwrapReleaseCond accepts exactly one `${{ }}` around the whole value,
// or none (E-4): GitHub reads `${{ a }} && ${{ b }}` as a non-empty
// string, which is true. The same holds for whitespace around the
// wrapper (#77 review A, B1): a block scalar (`if: |`) keeps a trailing
// newline, a quoted value keeps its spaces, and GitHub then reads the
// value as a non-empty string, which is true. So a value with `${{` is
// refused unless it equals its strings.TrimSpace (Unicode whitespace
// included), never trimmed.
func unwrapReleaseCond(s string) (string, error) {
	if strings.Contains(s, "${{") && s != strings.TrimSpace(s) {
		return "", stringCondError(fmt.Sprintf("whitespace around the ${{ }} (%q): GitHub reads such a value as a string, which is true", s))
	}
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "${{") {
		if !strings.HasSuffix(s, "}}") {
			return "", stringCondError("text after the closing }}: the ${{ }} must wrap the whole value; GitHub reads such a value as a string, which is true")
		}
		inner := s[len("${{") : len(s)-len("}}")]
		if strings.Contains(inner, "${{") || strings.Contains(inner, "}}") {
			return "", stringCondError("more than one ${{ }}: GitHub reads such a value as a string, which is true")
		}
		s = inner
	} else if strings.Contains(s, "${{") {
		return "", stringCondError("text outside the ${{ }}: GitHub reads such a value as a string, which is true")
	}
	if strings.TrimSpace(s) == "" {
		return "", errors.New("an empty condition")
	}
	return s, nil
}

// condTokens splits a condition into its tokens.
func condTokens(s string) ([]string, error) {
	var out []string
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case strings.HasPrefix(s[i:], "&&"), strings.HasPrefix(s[i:], "||"), strings.HasPrefix(s[i:], "=="), strings.HasPrefix(s[i:], "!="),
			strings.HasPrefix(s[i:], "<="), strings.HasPrefix(s[i:], ">="):
			out = append(out, s[i:i+2])
			i += 2
		case strings.ContainsRune("!()<>,[]*", rune(c)):
			out = append(out, string(c))
			i++
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, errors.New("an unterminated string")
			}
			out = append(out, s[i:i+j+2])
			i += j + 2
		default:
			j := i
			for j < len(s) && (s[j] == '_' || s[j] == '-' || s[j] == '.' ||
				'a' <= s[j] && s[j] <= 'z' || 'A' <= s[j] && s[j] <= 'Z' || '0' <= s[j] && s[j] <= '9') {
				j++
			}
			if j == i {
				return nil, fmt.Errorf("the character %q", c)
			}
			out = append(out, s[i:j])
			i = j
		}
	}
	return out, nil
}

// condParser is a recursive-descent parser of the grammar above, with
// GitHub's precedence: ! before && before ||.
type condParser struct {
	toks   []string
	pos    int
	direct []string
	status bool
}

func (p *condParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *condParser) next() string {
	t := p.peek()
	p.pos++
	return t
}

func (p *condParser) or() (*condNode, error) {
	left, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.peek() == "||" {
		p.next()
		right, err := p.and()
		if err != nil {
			return nil, err
		}
		left = &condNode{op: "or", kids: []*condNode{left, right}}
	}
	return left, nil
}

func (p *condParser) and() (*condNode, error) {
	left, err := p.unary()
	if err != nil {
		return nil, err
	}
	for p.peek() == "&&" {
		p.next()
		right, err := p.unary()
		if err != nil {
			return nil, err
		}
		left = &condNode{op: "and", kids: []*condNode{left, right}}
	}
	return left, nil
}

func (p *condParser) unary() (*condNode, error) {
	if p.peek() != "!" {
		return p.primary()
	}
	p.next()
	if strings.HasPrefix(p.peek(), "needs.") {
		// GitHub binds ! to needs.<j>.result alone, not to the comparison.
		return nil, fmt.Errorf("! before %s negates the result, not the comparison", p.peek())
	}
	k, err := p.unary()
	if err != nil {
		return nil, err
	}
	return &condNode{op: "not", kids: []*condNode{k}}, nil
}

func (p *condParser) primary() (*condNode, error) {
	t := p.next()
	switch {
	case t == "(":
		n, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.next() != ")" {
			return nil, errors.New("an unbalanced (")
		}
		return n, nil
	case t == "inputs.dry_run":
		return &condNode{op: "dry"}, nil
	case condStatusFns[t]:
		if p.next() != "(" || p.next() != ")" {
			return nil, fmt.Errorf("%s without ()", t)
		}
		p.status = true
		return &condNode{op: "fn", name: t}, nil
	case condNeedsResult.MatchString(t):
		need := condNeedsResult.FindStringSubmatch(t)[1]
		if !slices.Contains(p.direct, need) {
			return nil, fmt.Errorf("%s is not a direct need: needs.<j>.result exists only for direct needs, and reads as empty otherwise", need)
		}
		if op := p.next(); op != "==" {
			return nil, fmt.Errorf("%s %s: only == 'success' is in the grammar", t, op)
		}
		if v := p.next(); v != "'success'" {
			return nil, fmt.Errorf("%s == %s: only == 'success' is in the grammar", t, v)
		}
		return &condNode{op: "need", name: need}, nil
	case strings.HasPrefix(t, "'"):
		return nil, fmt.Errorf("the string %s: a comparison is written needs.<j>.result == 'success'", t)
	case t == "":
		return nil, errors.New("the condition ends early")
	}
	return nil, fmt.Errorf("the term %q", t)
}

// parseReleaseCond parses a job's `if` value against its direct needs.
func parseReleaseCond(v any, direct []string) (releaseCond, error) {
	s, ok := v.(string)
	if !ok {
		return releaseCond{}, fmt.Errorf("the value %#v is not a string", v)
	}
	inner, err := unwrapReleaseCond(s)
	if err != nil {
		return releaseCond{}, err
	}
	toks, err := condTokens(inner)
	if err != nil {
		return releaseCond{}, err
	}
	p := &condParser{toks: toks, direct: direct}
	root, err := p.or()
	if err != nil {
		return releaseCond{}, err
	}
	if p.pos < len(p.toks) {
		return releaseCond{}, fmt.Errorf("the term %q after a complete condition", p.toks[p.pos])
	}
	return releaseCond{root: root, status: p.status}, nil
}

// releaseRun is one simulated run: the mode, and each job's ancestors and
// result (success, failure or skipped).
type releaseRun struct {
	dry    bool
	anc    map[string]map[string]bool
	result map[string]string
}

func (r releaseRun) success(job string) bool {
	for a := range r.anc[job] {
		if r.result[a] != "success" {
			return false
		}
	}
	return true
}

func (r releaseRun) failure(job string) bool {
	for a := range r.anc[job] {
		if r.result[a] == "failure" {
			return true
		}
	}
	return false
}

func (r releaseRun) eval(job string, n *condNode) bool {
	switch n.op {
	case "and":
		return r.eval(job, n.kids[0]) && r.eval(job, n.kids[1])
	case "or":
		return r.eval(job, n.kids[0]) || r.eval(job, n.kids[1])
	case "not":
		return !r.eval(job, n.kids[0])
	case "dry":
		return r.dry
	case "need":
		return r.result[n.name] == "success"
	case "true": // a value GitHub reads as a non-empty string
		return true
	}
	switch n.name {
	case "success":
		return r.success(job)
	case "failure":
		return r.failure(job)
	case "always":
		return true
	}
	return false // cancelled(): no run is cancelled here
}

// runs reports whether a job starts: an `if` without a status function
// gets the implicit success() (rule 1), and no `if` is success() alone.
func (r releaseRun) runs(job string, c releaseCond) bool {
	if c.root == nil {
		return r.success(job)
	}
	if !c.status && !r.success(job) {
		return false
	}
	return r.eval(job, c.root)
}

// simulateRelease runs every job in topological order in one mode, every
// job that runs passing except failing ("" for none). It returns the jobs
// that started (the failing one included).
func simulateRelease(g releaseGraph, conds map[string]releaseCond, dry bool, failing string) []string {
	r := releaseRun{dry: dry, anc: map[string]map[string]bool{}, result: map[string]string{}}
	var started []string
	for _, j := range releaseTopo(g) {
		r.anc[j] = releaseAncestors(g.needs, j)
		if !r.runs(j, conds[j]) {
			r.result[j] = "skipped"
			continue
		}
		started = append(started, j)
		r.result[j] = "success"
		if j == failing {
			r.result[j] = "failure"
		}
	}
	return started
}

// setDiff names the jobs of want missing from got and the extra ones.
func setDiff(got, want []string) (missing, extra []string) {
	for _, w := range want {
		if !slices.Contains(got, w) {
			missing = append(missing, w)
		}
	}
	for _, g := range got {
		if !slices.Contains(want, g) {
			extra = append(extra, g)
		}
	}
	return missing, extra
}

func describeDiff(missing, extra []string) string {
	var parts []string
	if len(missing) > 0 {
		parts = append(parts, "missing "+strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		parts = append(parts, "extra "+strings.Join(extra, ", "))
	}
	return strings.Join(parts, "; ")
}

func modeWord(dry bool) string {
	if dry {
		return "dry"
	}
	return "real"
}

// checkReleaseGraph applies principle A to release.yml's jobs. It returns
// the jobs whose `if` the form rule holds; P6 does not compare those
// again.
func checkReleaseGraph(jobsNode *yaml.Node, line int, add func(int, string, ...any)) map[string]bool {
	g := readReleaseGraph(jobsNode)
	if releaseGraphProblems(g, add) {
		return nil
	}
	formJobs := map[string]bool{}
	conds := map[string]releaseCond{}
	grammarOK := true
	for _, j := range g.order {
		v, has := g.cond[j]
		if !has {
			continue
		}
		c, err := parseReleaseCond(v, g.needs[j])
		if err != nil {
			add(g.line[j], "job %s: rule 7 cannot evaluate its if (%v): it reads only ${{ }} around the whole value, !, &&, ||, parentheses, inputs.dry_run, needs.<direct need>.result == 'success' and success(), failure(), cancelled() and always(), and refuses a condition it cannot evaluate (#77)", j, err)
			var asString stringCondError
			if errors.As(err, &asString) {
				conds[j] = releaseCond{root: &condNode{op: "true"}}
				continue
			}
			grammarOK = false
			continue
		}
		conds[j] = c
	}
	// Form: the jobs with a mode-exclusive ancestor in the workflow, whose
	// needs are the policy's (otherwise P6 reports the needs, and compares
	// the if with the policy's).
	for _, j := range g.order {
		p, ok := releaseJobs[j]
		if !ok || !slices.Equal(sortedCopy(g.needs[j]), sortedCopy(p.needs)) {
			continue
		}
		anc := exclusiveAncestor(g.needs, j, releaseJobOrder)
		if anc == "" {
			continue
		}
		formJobs[j] = true
		want := releaseExplicitCond(releaseJobMode(j), p.needs)
		got, isString := g.cond[j].(string)
		// Exactly, not trimmed (#77 review A, B1).
		if !isString || got != want {
			other := "real"
			if releaseJobMode(anc) == modeReal {
				other = "dry"
			}
			shown := "(none)"
			if v, has := g.cond[j]; has {
				shown = fmt.Sprint(v)
			}
			add(g.line[j], "job %s: if must be exactly %s (P6, #77): its ancestor %s is skipped in a %s run, and a bare if gets an implicit success() over every ancestor, which a skipped one makes false; so a job after a job of one mode spells out !cancelled(), its mode and each need's result, in the policy's needs order; got %s",
				j, want, anc, other, shown)
		}
	}
	if !grammarOK {
		return formJobs
	}
	for _, p := range releaseSimProblems(g, conds) {
		l := line
		if p.job != "" {
			l = g.line[p.job]
		}
		add(l, "%s", p.msg)
	}
	return formJobs
}

// simProblem is a finding of the simulation, at a job's line ("" for the
// jobs key).
type simProblem struct {
	job, msg string
}

// releaseSimProblems simulates both modes: the jobs that run must be
// exactly the planned set, and in a mode whose set is right, each job of
// it failing must skip exactly its descendants (failure injection).
func releaseSimProblems(g releaseGraph, conds map[string]releaseCond) []simProblem {
	var out []simProblem
	for _, dry := range []bool{true, false} {
		want := releaseRealJobs
		if dry {
			want = releaseDryJobs
		}
		got := simulateRelease(g, conds, dry, "")
		if missing, extra := setDiff(got, want); len(missing)+len(extra) > 0 {
			out = append(out, simProblem{"", fmt.Sprintf("release.yml: in a %s run the jobs that run must be exactly %s, but the conditions give %s (#77)", modeWord(dry), strings.Join(want, ", "), describeDiff(missing, extra))})
			continue
		}
		for _, f := range want {
			var expect []string
			for _, j := range want {
				if !releaseAncestors(g.needs, j)[f] {
					expect = append(expect, j)
				}
			}
			got := simulateRelease(g, conds, dry, f)
			if missing, extra := setDiff(got, expect); len(missing)+len(extra) > 0 {
				out = append(out, simProblem{f, fmt.Sprintf("release.yml: in a %s run where %s fails, the conditions give %s: a job after a failed need must be skipped, every other job must still run (#77)", modeWord(dry), f, describeDiff(missing, extra))})
			}
		}
	}
	return out
}
