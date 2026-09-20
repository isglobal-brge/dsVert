package main

import (
	"crypto/sha256"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestGroupedLMMMomentSchedule(t *testing.T) {
	p := groupedLMMMomentPlan{Clusters: 3, Slots: 4, Columns: 4}
	rows, a, b := make([]groupedWord, 48), make([]groupedWord, 48), make([]groupedWord, 48)
	for i := range rows {
		// Exact f50 source values, with the last cluster inactive.
		if i < 32 {
			rows[i] = groupedWord{uint64(i%4+1) << 48, 0, 0}
		}
		var err error
		a[i], err = groupedRandomWord()
		if err != nil {
			t.Fatal(err)
		}
		b[i] = rows[i].sub(a[i])
	}
	ma, err := groupedLMMPrepareMoments(p, a)
	if err != nil {
		t.Fatal(err)
	}
	mb, err := groupedLMMPrepareMoments(p, b)
	if err != nil {
		t.Fatal(err)
	}
	for start := 0; start < p.products(); start += 17 {
		count := 17
		if start+count > p.products() {
			count = p.products() - start
		}
		ax, ay, err := ma.operands(a, start, count)
		if err != nil {
			t.Fatal(err)
		}
		bx, by, err := mb.operands(b, start, count)
		if err != nil {
			t.Fatal(err)
		}
		za, zb := make([]groupedWord, count), make([]groupedWord, count)
		for i := range za {
			za[i], err = groupedRandomWord()
			if err != nil {
				t.Fatal(err)
			}
			zb[i] = ax[i].add(bx[i]).mul(ay[i].add(by[i])).sub(za[i])
		}
		if err = ma.accumulate(start, za); err != nil {
			t.Fatal(err)
		}
		if err = mb.accumulate(start, zb); err != nil {
			t.Fatal(err)
		}
	}
	for c := 0; c < p.Clusters; c++ {
		for k := 0; k < p.triangle(); k++ {
			j, l := p.pair(k)
			sj, sl, within := new(big.Int), new(big.Int), new(big.Int)
			for r := 0; r < p.Slots; r++ {
				x := groupedWordBig(rows[(c*p.Slots+r)*p.Columns+j])
				y := groupedWordBig(rows[(c*p.Slots+r)*p.Columns+l])
				sj.Add(sj, x)
				sl.Add(sl, y)
				within.Add(within, new(big.Int).Mul(x, y))
			}
			idx := c*p.triangle() + k
			if groupedWordBig(ma.Within[idx].add(mb.Within[idx])).Cmp(within) != 0 {
				t.Fatal("within oracle mismatch")
			}
			if groupedWordBig(ma.Between[idx].add(mb.Between[idx])).Cmp(new(big.Int).Mul(sj, sl)) != 0 {
				t.Fatal("between oracle mismatch")
			}
		}
	}
}
func TestGroupedLMMMomentAdmission(t *testing.T) {
	for _, p := range []groupedLMMMomentPlan{{0, 4, 3}, {2, 33, 3}, {10000, 32, 3}, {2, 4, 2}, {2, 4, 19}} {
		if p.validate() == nil {
			t.Fatal("bad shape accepted")
		}
	}
	p := groupedLMMMomentPlan{2, 4, 3}
	rows := make([]groupedWord, 24)
	m, err := groupedLMMPrepareMoments(p, rows)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]int{{-1, 1}, {0, 0}, {0, 1025}, {p.products(), 1}} {
		if _, _, err = m.operands(rows, pair[0], pair[1]); err == nil {
			t.Fatal("bad chunk accepted")
		}
	}
	if err = m.accumulate(p.products(), []groupedWord{{}}); err == nil {
		t.Fatal("bad accumulation accepted")
	}
}

func TestGroupedLMMMomentsTwoAuthority(t *testing.T) {
	p := groupedLMMMomentPlan{Clusters: 2, Slots: 2, Columns: 3}
	rows := []groupedWord{{1 << 50, 0, 0}, {1 << 49, 0, 0}, {1 << 48, 0, 0}, {1 << 50, 0, 0}, {1 << 48, 0, 0}, {1 << 49, 0, 0}, {}, {}, {}, {}, {}, {}}
	a, b := make([]groupedWord, len(rows)), make([]groupedWord, len(rows))
	for i := range rows {
		var err error
		a[i], err = groupedRandomWord()
		if err != nil {
			t.Fatal(err)
		}
		b[i] = rows[i].sub(a[i])
	}
	ma, err := groupedLMMPrepareMoments(p, a)
	if err != nil {
		t.Fatal(err)
	}
	mb, err := groupedLMMPrepareMoments(p, b)
	if err != nil {
		t.Fatal(err)
	}
	ax, ay, err := ma.operands(a, 0, p.products())
	if err != nil {
		t.Fatal(err)
	}
	bx, by, err := mb.operands(b, 0, p.products())
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	left.SetDeadline(time.Now().Add(time.Minute))
	right.SetDeadline(time.Now().Add(time.Minute))
	session := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 192, VectorLen: 1})
	plan := groupedArithmeticPlan{Count: p.products(), Contract: sha256.Sum256([]byte("LMM synthetic moments"))}
	type result struct {
		value *groupedArithmeticResult
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		v, err := groupedArithmeticProduct(left, session, exactGCRoleGarbler, plan, ax, ay)
		if err != nil {
			left.Close()
		}
		ch <- result{v, err}
	}()
	v, err := groupedArithmeticProduct(right, session, exactGCRoleEvaluator, plan, bx, by)
	if err != nil {
		right.Close()
	}
	peer := <-ch
	if err != nil || peer.err != nil {
		t.Fatalf("protocol %v / %v", err, peer.err)
	}
	if err = ma.accumulate(0, peer.value.Shares); err != nil {
		t.Fatal(err)
	}
	if err = mb.accumulate(0, v.Shares); err != nil {
		t.Fatal(err)
	}
	ref, err := groupedLMMPrepareMoments(p, rows)
	if err != nil {
		t.Fatal(err)
	}
	x, y, err := ref.operands(rows, 0, p.products())
	if err != nil {
		t.Fatal(err)
	}
	products := make([]groupedWord, len(x))
	for i := range x {
		products[i] = x[i].mul(y[i])
	}
	if err = ref.accumulate(0, products); err != nil {
		t.Fatal(err)
	}
	for i := range ref.Within {
		if ma.Within[i].add(mb.Within[i]) != ref.Within[i] || ma.Between[i].add(mb.Between[i]) != ref.Between[i] {
			t.Fatal("two-authority moments mismatch")
		}
	}
}
