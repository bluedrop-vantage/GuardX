package secrets

// Minimal Aho-Corasick trie: case-insensitive membership over the union of
// rule keywords, used to prefilter which rules run their regex.
//
// Not a competitive AC implementation — enough to skip cold regexes on
// generic prose. For the tight ruleset in M1 (<20 keywords) this suffices;
// swap in cloudflare/ahocorasick when the ruleset grows.

type ahoTrie struct {
	root *ahoNode
}

type ahoNode struct {
	next    map[byte]*ahoNode
	fail    *ahoNode
	outputs []string
}

func buildAho(keywords []string) *ahoTrie {
	if len(keywords) == 0 {
		return nil
	}
	t := &ahoTrie{root: &ahoNode{next: map[byte]*ahoNode{}}}
	// Deduplicate + normalize.
	seen := map[string]bool{}
	for _, k := range keywords {
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		t.insert(k)
	}
	t.buildFailLinks()
	return t
}

func (t *ahoTrie) insert(pat string) {
	n := t.root
	for i := 0; i < len(pat); i++ {
		b := toLower(pat[i])
		if next, ok := n.next[b]; ok {
			n = next
			continue
		}
		child := &ahoNode{next: map[byte]*ahoNode{}}
		n.next[b] = child
		n = child
	}
	n.outputs = append(n.outputs, pat)
}

func (t *ahoTrie) buildFailLinks() {
	queue := []*ahoNode{}
	for _, c := range t.root.next {
		c.fail = t.root
		queue = append(queue, c)
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for b, c := range n.next {
			// Walk failure links to find the longest proper suffix.
			f := n.fail
			for f != nil {
				if nx, ok := f.next[b]; ok {
					c.fail = nx
					break
				}
				f = f.fail
			}
			if c.fail == nil {
				c.fail = t.root
			}
			c.outputs = append(c.outputs, c.fail.outputs...)
			queue = append(queue, c)
		}
	}
}

// matchKeywords returns the deduplicated set of keywords found in text.
func (t *ahoTrie) matchKeywords(text string) []string {
	if t == nil {
		return nil
	}
	found := map[string]bool{}
	n := t.root
	for i := 0; i < len(text); i++ {
		b := toLower(text[i])
		for {
			if nx, ok := n.next[b]; ok {
				n = nx
				break
			}
			if n == t.root {
				break
			}
			n = n.fail
		}
		for _, kw := range n.outputs {
			found[kw] = true
		}
	}
	out := make([]string, 0, len(found))
	for k := range found {
		out = append(out, k)
	}
	return out
}

func toLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}
