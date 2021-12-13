package parser

import "errors"

func badErr(gotErr, wantErr error) bool {
	bad := false
	if gotErr == nil {
		if wantErr != nil {
			bad = true
		}
	} else if !errors.Is(gotErr, wantErr) {
		bad = true
	}
	return bad
}

// isEqual returns true if all of the elements in s1 exist in s2.
func isEqual(s1, s2 []string) bool {
	if s1 == nil && s2 == nil {
		return true
	}
	if (s1 == nil && s2 != nil) || (s1 != nil && s2 == nil) {
		return false
	}
	if len(s1) != len(s2) {
		return false
	}
	diff := make(map[string]int, len(s1))
	for _, s := range s1 {
		diff[s]++
	}
	for _, s := range s2 {
		if _, ok := diff[s]; !ok {
			return false
		}
		diff[s]--
		if diff[s] == 0 {
			delete(diff, s)
		}
	}
	return len(diff) == 0
}
