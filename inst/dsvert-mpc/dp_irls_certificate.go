package main

// The producer certificate is deliberately separate from B1's public-update
// certificate. A syntactically valid signed B1 path does not admit a circuit.
import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const dpIRLSProducerProfileVersion = "dsvert-dp-irls-producer-p3-q16-q12-v1"
const dpIRLSProducerCertificateDomain = "dsvert-dp-irls-producer-certificate-v1\x00"

// Fields are lexicographically ordered. Numeric metadata uses integer strings,
// and errors use B1's reduced rational ABI, so R and Go hash identical bytes.
type dpIRLSProducerProfile struct {
	ETARoundingError     dpIRLSRat `json:"eta_rounding_error"`
	Family               string    `json:"family"`
	GCap                 int64     `json:"g_cap,string"`
	GTranslation         int64     `json:"g_translation,string"`
	HCap                 int64     `json:"h_cap,string"`
	HCoordinateError     dpIRLSRat `json:"h_coordinate_error"`
	HTranslation         int64     `json:"h_translation,string"`
	IntermediateBits     int       `json:"intermediate_bits,string"`
	LinkError            dpIRLSRat `json:"link_error"`
	LinkProfileSHA256    string    `json:"link_profile_sha256"`
	OutputFractionBits   int       `json:"output_fraction_bits,string"`
	P                    int       `json:"p,string"`
	RingBits             int       `json:"ring_bits,string"`
	RowCap               int       `json:"row_cap,string"`
	Rows                 int       `json:"rows,string"`
	S1G                  int64     `json:"s1_g,string"`
	S1H                  int64     `json:"s1_h,string"`
	ScoreCoordinateError dpIRLSRat `json:"score_coordinate_error"`
	SourceFractionBits   int       `json:"source_fraction_bits,string"`
	Version              string    `json:"version"`
}

func dpIRLSProducerCertificate(family string, p, rows, rowCap int) (dpIRLSProducerProfile, error) {
	if p != 3 || rows < 1 || rows > 64 || rowCap != 1 || (family != "binomial" && family != "poisson") {
		return dpIRLSProducerProfile{}, fmt.Errorf("dp IRLS producer: uncertified family or public shape")
	}
	c := dpIRLSProducerProfile{
		ETARoundingError: dpIRLSRat{D: "131072", N: "1"}, Family: family,
		GCap: 4096, HCap: 1024, IntermediateBits: 64,
		LinkError:         dpIRLSRat{D: "327680", N: "69"},
		LinkProfileSHA256: groupedProfileSHA256, OutputFractionBits: 12,
		P: p, RingBits: 128, RowCap: rowCap, Rows: rows,
		ScoreCoordinateError: dpIRLSRat{D: "2621440", N: "877"},
		HCoordinateError:     dpIRLSRat{D: "2621440", N: "897"},
		SourceFractionBits:   16, Version: dpIRLSProducerProfileVersion,
	}
	if family == "poisson" {
		c.GCap, c.HCap = 225280, 225280 // 55 * 2^12.
		c.LinkError = dpIRLSRat{D: "2000", N: "11"}
		c.ScoreCoordinateError = dpIRLSRat{D: "16384000", N: "98987"}
		c.HCoordinateError = c.ScoreCoordinateError
	}
	// |x|<=1, |r|<=R and 0<=w<=W are enforced before exact products.
	// R*2^12 and W*2^12 are integers. Monotonic nearest-even rounding
	// preserves these closed integer endpoints, giving tighter final caps
	// than adding a half-unit to every coordinate before taking ceilings.
	c.GTranslation, c.HTranslation = int64(rows)*c.GCap, int64(rows)*c.HCap
	c.S1G, c.S1H = 3*c.GCap, 6*c.HCap // Replace-person multiplies both by two.
	return c, nil
}

func dpIRLSProducerCertificateDigest(c dpIRLSProducerProfile) string {
	b, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	h := sha256.Sum256(append([]byte(dpIRLSProducerCertificateDomain), b...))
	return hex.EncodeToString(h[:])
}
