package scan

// matcher is an ASCII-case-folded Aho-Corasick automaton compiled down to a
// dense DFA: exactly one table lookup per input byte, with no fail-link walking
// at match time. It answers a single question for a whole text in one pass:
// which of the N patterns occur at least once?
//
// The gitleaks rule set carries ~290 keywords across ~220 rules. Testing them
// with strings.Contains costs one full pass per keyword (measured 10.8ms for a
// 187KB payload); the automaton replaces that with a single pass.
type matcher struct {
	// next is the flattened transition table: next[state<<8|byte].
	next []int32
	// emit[state] lists the pattern ids that end at this state (suffix
	// outputs already merged in, so a state's list is complete).
	emit [][]int32
}

func foldByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// newMatcher compiles patterns into the automaton. Empty patterns are ignored;
// pattern ids are the indexes into the supplied slice.
func newMatcher(patterns []string) *matcher {
	type node struct {
		next [256]int32
		emit []int32
		fail int32
	}
	newNode := func() node {
		var n node
		for i := range n.next {
			n.next[i] = -1
		}
		return n
	}
	nodes := []node{newNode()}

	for id, pattern := range patterns {
		if pattern == "" {
			continue
		}
		cur := int32(0)
		for i := 0; i < len(pattern); i++ {
			c := foldByte(pattern[i])
			if nodes[cur].next[c] < 0 {
				nodes = append(nodes, newNode())
				nodes[cur].next[c] = int32(len(nodes) - 1)
			}
			cur = nodes[cur].next[c]
		}
		nodes[cur].emit = append(nodes[cur].emit, int32(id))
	}

	// Breadth-first pass: resolve fail links, merge suffix outputs, and turn
	// the goto function into a total transition function.
	queue := make([]int32, 0, len(nodes))
	for c := 0; c < 256; c++ {
		child := nodes[0].next[c]
		if child < 0 {
			nodes[0].next[c] = 0
			continue
		}
		nodes[child].fail = 0
		queue = append(queue, child)
	}
	for i := 0; i < len(queue); i++ {
		u := queue[i]
		if suffix := nodes[nodes[u].fail].emit; len(suffix) > 0 {
			merged := make([]int32, 0, len(nodes[u].emit)+len(suffix))
			merged = append(merged, nodes[u].emit...)
			merged = append(merged, suffix...)
			nodes[u].emit = merged
		}
		for c := 0; c < 256; c++ {
			child := nodes[u].next[c]
			fallback := nodes[nodes[u].fail].next[c]
			if child < 0 {
				nodes[u].next[c] = fallback
				continue
			}
			nodes[child].fail = fallback
			queue = append(queue, child)
		}
	}

	m := &matcher{
		next: make([]int32, len(nodes)*256),
		emit: make([][]int32, len(nodes)),
	}
	for i := range nodes {
		copy(m.next[i*256:(i+1)*256], nodes[i].next[:])
		m.emit[i] = nodes[i].emit
	}
	return m
}

// scan marks hit[id] for every pattern id that occurs in text.
func (m *matcher) scan(text string, hit []bool) {
	state := int32(0)
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		state = m.next[int(state)<<8|int(c)]
		if emit := m.emit[state]; len(emit) != 0 {
			for _, id := range emit {
				hit[id] = true
			}
		}
	}
}
