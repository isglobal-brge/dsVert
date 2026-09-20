package main

// The stage plan is semantic and stable across fresh protocol attempts. A
// stage receipt contains attempt commitments and must never enter the sampler
// digest: doing so would derive another noise stream after recovery.
import (
	"encoding/hex"
	"fmt"
	"strings"
)

func (s jointDPVectorSpec) validateSourcePlan() error {
	if s.SourceStagePlanDigest == "" {
		return nil
	}
	raw, err := hex.DecodeString(s.SourceStagePlanDigest)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != s.SourceStagePlanDigest ||
		s.SourceStagePlanDigest == strings.Repeat("0", 64) ||
		(4*128+4*s.BinaryGeometricBits*s.UniformBits+2)*s.CoordinateCount+1 > exactGCMaxCircuitTypeBits {
		return fmt.Errorf("joint-dp-vector-gc: invalid staged source plan")
	}
	return nil
}

func (s jointDPVectorSpec) validateSourceValidity(values [][]bool) error {
	if s.SourceStagePlanDigest == "" {
		if len(values) == 0 || (len(values) == 1 && len(values[0]) == 0) {
			return nil
		}
	} else if len(values) == 1 && len(values[0]) == s.CoordinateCount {
		return nil
	}
	return fmt.Errorf("joint-dp-vector-gc: invalid private source validity")
}

func (s jointDPVectorSpec) decodeSourceValidity(encoded string) ([]bool, error) {
	if s.SourceStagePlanDigest == "" {
		if encoded == "" {
			return nil, nil
		}
		return nil, fmt.Errorf("joint-dp-vector-gc: unexpected source validity")
	}
	raw, err := exactGCStrictBase64(encoded, (s.CoordinateCount+7)/8)
	if err != nil {
		return nil, fmt.Errorf("joint-dp-vector-gc: missing private source validity")
	}
	defer clear(raw)
	if remainder := s.CoordinateCount % 8; remainder != 0 && raw[len(raw)-1]>>remainder != 0 {
		return nil, fmt.Errorf("joint-dp-vector-gc: noncanonical source validity")
	}
	values := make([]bool, s.CoordinateCount)
	for i := range values {
		values[i] = raw[i/8]&(1<<uint(i%8)) != 0
	}
	return values, nil
}
