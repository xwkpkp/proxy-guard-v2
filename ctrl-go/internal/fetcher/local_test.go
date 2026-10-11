package fetcher

import (
	"context"
	"testing"
)

func TestLocalFetcherBatchAndUniqueness(t *testing.T) {
	f := NewLocal(50, 2, 42)
	out := make(chan Target, 128)
	if err := f.Fetch(context.Background(), out); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	close(out)

	seen := make(map[string]bool)
	count := 0
	for tgt := range out {
		key := tgt.Key()
		if seen[key] {
			t.Fatalf("duplicate target %s", key)
		}
		seen[key] = true
		count++
		if tgt.Source == "" {
			t.Fatal("target without source")
		}
	}
	if count != 50 {
		t.Fatalf("expected 50 targets, got %d", count)
	}
}

func TestLocalFetcherRoundsVary(t *testing.T) {
	f := NewLocal(40, 2, 7)
	collect := func() map[string]bool {
		out := make(chan Target, 128)
		if err := f.Fetch(context.Background(), out); err != nil {
			t.Fatalf("fetch: %v", err)
		}
		close(out)
		set := make(map[string]bool)
		for tgt := range out {
			set[tgt.Key()] = true
		}
		return set
	}
	first := collect()
	second := collect()
	same := true
	for k := range first {
		if !second[k] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("two fetch rounds produced identical batches; seed should advance")
	}
}
