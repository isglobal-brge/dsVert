package main

// Candidate-independent sufficient-statistic schedule for LMM. Inputs are
// already privately aligned, masked and routed ONCE into public B-slot blocks.
// Columns are (live*f50, live*x1*f50, ..., live*y*f50). A local constructor
// cannot certify those preconditions: Step 2 must bind them to source/primitive
// receipts. Nothing in this file authorizes a source read or DP release.
import "fmt"

type groupedLMMMomentPlan struct{ Clusters, Slots, Columns int }
type groupedLMMMoments struct {
	Plan    groupedLMMMomentPlan
	Sums    []groupedWord
	Within  []groupedWord // each cluster's upper triangle sum_i z_i z_i^T, f100
	Between []groupedWord // each cluster's upper triangle (sum_i z_i)(sum_i z_i)^T, f100
}

func (p groupedLMMMomentPlan) validate() error {
	if p.Clusters < 1 || p.Slots < 1 || p.Slots > 32 || p.Clusters > 16384/p.Slots || p.Columns < 3 || p.Columns > 18 {
		return fmt.Errorf("grouped moments rejected")
	}
	return nil
}
func (p groupedLMMMomentPlan) triangle() int { return p.Columns * (p.Columns + 1) / 2 }
func (p groupedLMMMomentPlan) products() int { return p.Clusters * (p.Slots + 1) * p.triangle() }
func groupedLMMPrepareMoments(p groupedLMMMomentPlan, rows []groupedWord) (*groupedLMMMoments, error) {
	if p.validate() != nil || len(rows) != p.Clusters*p.Slots*p.Columns {
		return nil, fmt.Errorf("grouped moments rejected")
	}
	m := &groupedLMMMoments{Plan: p, Sums: make([]groupedWord, p.Clusters*p.Columns), Within: make([]groupedWord, p.Clusters*p.triangle()), Between: make([]groupedWord, p.Clusters*p.triangle())}
	for c := 0; c < p.Clusters; c++ {
		for r := 0; r < p.Slots; r++ {
			for k := 0; k < p.Columns; k++ {
				m.Sums[c*p.Columns+k] = m.Sums[c*p.Columns+k].add(rows[(c*p.Slots+r)*p.Columns+k])
			}
		}
	}
	return m, nil
}
func (p groupedLMMMomentPlan) pair(index int) (int, int) {
	for a := 0; a < p.Columns; a++ {
		width := p.Columns - a
		if index < width {
			return a, a + index
		}
		index -= width
	}
	panic("invalid internal triangle index")
}

// Public order: all within-row upper triangles, then cluster-sum triangles.
// The signed schedule uses exactly ceil(products/1024) checked-OT chunks.
func (m *groupedLMMMoments) operands(rows []groupedWord, start, count int) ([]groupedWord, []groupedWord, error) {
	p := m.Plan
	if p.validate() != nil || len(rows) != p.Clusters*p.Slots*p.Columns || len(m.Sums) != p.Clusters*p.Columns || start < 0 || count < 1 || count > 1024 || start > p.products()-count {
		return nil, nil, fmt.Errorf("grouped moments rejected")
	}
	x, y := make([]groupedWord, count), make([]groupedWord, count)
	within := p.Clusters * p.Slots * p.triangle()
	for i := range x {
		index := start + i
		data := rows
		if index >= within {
			index -= within
			data = m.Sums
		}
		a, b := p.pair(index % p.triangle())
		row := index / p.triangle()
		x[i] = data[row*p.Columns+a]
		y[i] = data[row*p.Columns+b]
	}
	return x, y, nil
}

// Called only on a complete authenticated chunk. Durable no-duplicate/no-skip
// enforcement belongs to Step 2; arithmetic output alone is not a receipt.
func (m *groupedLMMMoments) accumulate(start int, products []groupedWord) error {
	p := m.Plan
	if p.validate() != nil || len(m.Within) != p.Clusters*p.triangle() || len(m.Between) != len(m.Within) || start < 0 || len(products) < 1 || len(products) > 1024 || start > p.products()-len(products) {
		return fmt.Errorf("grouped moments rejected")
	}
	within := p.Clusters * p.Slots * p.triangle()
	for i, v := range products {
		index := start + i
		if index < within {
			cluster := index / (p.Slots * p.triangle())
			slot := cluster*p.triangle() + index%p.triangle()
			m.Within[slot] = m.Within[slot].add(v)
		} else {
			slot := index - within
			m.Between[slot] = m.Between[slot].add(v)
		}
	}
	return nil
}
