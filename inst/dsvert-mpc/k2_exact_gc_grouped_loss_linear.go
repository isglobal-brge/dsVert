package main

import "math/big"

// groupedShareBlockSums reduces already routed, already masked rows in fixed
// PUBLIC padded blocks. It cannot implement secret boundaries or masking.
// Values can be profile outputs or securely computed squares; never square an
// individual share here. Ring widths and fractional scales remain unchanged.
func groupedShareBlockSums(words []*big.Int, slots, columns, bits int) ([]*big.Int, error) {
	if slots < 1 || slots > 32 || columns < 1 || columns > 256 ||
		(bits != 32 && bits != 128 && bits != 192) || len(words) == 0 ||
		len(words)%(slots*columns) != 0 || primitiveVValidateWords(words, len(words), bits) != nil {
		return nil, primitiveVError()
	}
	out := make([]*big.Int, len(words)/slots)
	mod := exactGCModulus(bits)
	for block := 0; block < len(words)/(slots*columns); block++ {
		for column := 0; column < columns; column++ {
			sum := new(big.Int)
			for row := 0; row < slots; row++ {
				sum.Add(sum, words[(block*slots+row)*columns+column])
			}
			out[block*columns+column] = sum.Mod(sum, mod)
		}
	}
	return out, nil
}
