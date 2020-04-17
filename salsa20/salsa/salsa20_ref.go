// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package salsa

import (
	"encoding/binary"
	"math/bits"
)

const rounds = 20

func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	b ^= bits.RotateLeft32(a+d, 7)
	c ^= bits.RotateLeft32(b+a, 9)
	d ^= bits.RotateLeft32(c+b, 13)
	a ^= bits.RotateLeft32(d+c, 18)
	return a, b, c, d
}

const (
	j0 uint32 = 0x61707865 // expa
	j1 uint32 = 0x3320646e // nd 3
	j2 uint32 = 0x79622d32 // 2-by
	j3 uint32 = 0x6b206574 // te k
)

func keyStreamBlock(dst *[64]byte, nonce *[16]byte, key *[32]byte) {
	k0 := binary.LittleEndian.Uint32(key[0:4])
	k1 := binary.LittleEndian.Uint32(key[4:8])
	k2 := binary.LittleEndian.Uint32(key[8:12])
	k3 := binary.LittleEndian.Uint32(key[12:16])
	k4 := binary.LittleEndian.Uint32(key[16:20])
	k5 := binary.LittleEndian.Uint32(key[20:24])
	k6 := binary.LittleEndian.Uint32(key[24:28])
	k7 := binary.LittleEndian.Uint32(key[28:32])

	n0 := binary.LittleEndian.Uint32(nonce[0:4])
	n1 := binary.LittleEndian.Uint32(nonce[4:8])

	ctrLo := binary.LittleEndian.Uint32(nonce[8:12])
	ctrHi := binary.LittleEndian.Uint32(nonce[12:16])

	var (
		c0, c1, c2, c3     = j0, k0, k1, k2
		c4, c5, c6, c7     = k3, j1, n0, n1
		c10, c11           = j2, k4
		c12, c13, c14, c15 = k5, k6, k7, j3
	)

	x10, x14, x2, x6 := quarterRound(c10, c14, c2, c6)
	x15, x3, x7, x11 := quarterRound(c15, c3, c7, c11)
	x5, x9, x13, x1 := quarterRound(c5, ctrHi, c13, c1)
	x0, x4, x8, x12 := quarterRound(c0, c4, ctrLo, c12)

	x0, x1, x2, x3 = quarterRound(x0, x1, x2, x3)
	x5, x6, x7, x4 = quarterRound(x5, x6, x7, x4)
	x10, x11, x8, x9 = quarterRound(x10, x11, x8, x9)
	x15, x12, x13, x14 = quarterRound(x15, x12, x13, x14)

	// remaining 18 rounds
	for i := 0; i < rounds-2; i += 2 {
		// Odd round
		x0, x4, x8, x12 = quarterRound(x0, x4, x8, x12)
		x5, x9, x13, x1 = quarterRound(x5, x9, x13, x1)
		x10, x14, x2, x6 = quarterRound(x10, x14, x2, x6)
		x15, x3, x7, x11 = quarterRound(x15, x3, x7, x11)

		// Even round
		x0, x1, x2, x3 = quarterRound(x0, x1, x2, x3)
		x5, x6, x7, x4 = quarterRound(x5, x6, x7, x4)
		x10, x11, x8, x9 = quarterRound(x10, x11, x8, x9)
		x15, x12, x13, x14 = quarterRound(x15, x12, x13, x14)
	}

	binary.LittleEndian.PutUint32(dst[0:4], x0+c0)
	binary.LittleEndian.PutUint32(dst[4:8], x1+c1)
	binary.LittleEndian.PutUint32(dst[8:12], x2+c2)
	binary.LittleEndian.PutUint32(dst[12:16], x3+c3)
	binary.LittleEndian.PutUint32(dst[16:20], x4+c4)
	binary.LittleEndian.PutUint32(dst[20:24], x5+c5)
	binary.LittleEndian.PutUint32(dst[24:28], x6+c6)
	binary.LittleEndian.PutUint32(dst[28:32], x7+c7)
	binary.LittleEndian.PutUint32(dst[32:36], x8+ctrLo)
	binary.LittleEndian.PutUint32(dst[36:40], x9+ctrHi)
	binary.LittleEndian.PutUint32(dst[40:44], x10+c10)
	binary.LittleEndian.PutUint32(dst[44:48], x11+c11)
	binary.LittleEndian.PutUint32(dst[48:52], x12+c12)
	binary.LittleEndian.PutUint32(dst[52:56], x13+c13)
	binary.LittleEndian.PutUint32(dst[56:60], x14+c14)
	binary.LittleEndian.PutUint32(dst[60:64], x15+c15)
}

// xorKeyStreamBlocksGeneric encrypts all full blocks in src and writes to dst
// it leaves residual bytes that don't make up a full block untouched
func xorKeyStreamBlocksGeneric(dst, src []byte, nonce *[16]byte, key *[32]byte) {
	k0 := binary.LittleEndian.Uint32(key[0:4])
	k1 := binary.LittleEndian.Uint32(key[4:8])
	k2 := binary.LittleEndian.Uint32(key[8:12])
	k3 := binary.LittleEndian.Uint32(key[12:16])
	k4 := binary.LittleEndian.Uint32(key[16:20])
	k5 := binary.LittleEndian.Uint32(key[20:24])
	k6 := binary.LittleEndian.Uint32(key[24:28])
	k7 := binary.LittleEndian.Uint32(key[28:32])

	n0 := binary.LittleEndian.Uint32(nonce[0:4])
	n1 := binary.LittleEndian.Uint32(nonce[4:8])

	ctrLo := binary.LittleEndian.Uint32(nonce[8:12])
	ctrHi := binary.LittleEndian.Uint32(nonce[12:16])

	var (
		c0, c1, c2, c3     = j0, k0, k1, k2
		c4, c5, c6, c7     = k3, j1, n0, n1
		c10, c11           = j2, k4
		c12, c13, c14, c15 = k5, k6, k7, j3
	)

	// In the first round, there are two quarter rounds that remain
	// constant for all blocks.
	fr10, fr14, fr2, fr6 := quarterRound(c10, c14, c2, c6)
	fr15, fr3, fr7, fr11 := quarterRound(c15, c3, c7, c11)
	// The quarter round in first round involving the high 32 bits of the counter only
	// needs to be done when ctrHi increments, which doesn't happen for every block
	fr5, fr9, fr13, fr1 := quarterRound(c5, ctrHi, c13, c1)
	for len(src) >= 64 && len(dst) >= 64 { // check dst length to eliminate bounds check later in xor
		// This quarter round in first round needs to be recalculated for every block as it depends
		// on the low 32 bits of the counter
		fr0, fr4, fr8, fr12 := quarterRound(c0, c4, ctrLo, c12)

		// Second round
		x0, x1, x2, x3 := quarterRound(fr0, fr1, fr2, fr3)
		x5, x6, x7, x4 := quarterRound(fr5, fr6, fr7, fr4)
		x10, x11, x8, x9 := quarterRound(fr10, fr11, fr8, fr9)
		x15, x12, x13, x14 := quarterRound(fr15, fr12, fr13, fr14)

		// remaining 18 rounds
		for i := 0; i < rounds-2; i += 2 {
			// Odd round
			x0, x4, x8, x12 = quarterRound(x0, x4, x8, x12)
			x5, x9, x13, x1 = quarterRound(x5, x9, x13, x1)
			x10, x14, x2, x6 = quarterRound(x10, x14, x2, x6)
			x15, x3, x7, x11 = quarterRound(x15, x3, x7, x11)

			// Even round
			x0, x1, x2, x3 = quarterRound(x0, x1, x2, x3)
			x5, x6, x7, x4 = quarterRound(x5, x6, x7, x4)
			x10, x11, x8, x9 = quarterRound(x10, x11, x8, x9)
			x15, x12, x13, x14 = quarterRound(x15, x12, x13, x14)
		}

		// Add the initial state to get the key stream block,
		// XOR with the source and write out the result.
		xor(dst[0:4], src[0:4], x0+c0)
		xor(dst[4:8], src[4:8], x1+c1)
		xor(dst[8:12], src[8:12], x2+c2)
		xor(dst[12:16], src[12:16], x3+c3)
		xor(dst[16:20], src[16:20], x4+c4)
		xor(dst[20:24], src[20:24], x5+c5)
		xor(dst[24:28], src[24:28], x6+c6)
		xor(dst[28:32], src[28:32], x7+c7)
		xor(dst[32:36], src[32:36], x8+ctrLo)
		xor(dst[36:40], src[36:40], x9+ctrHi)
		xor(dst[40:44], src[40:44], x10+c10)
		xor(dst[44:48], src[44:48], x11+c11)
		xor(dst[48:52], src[48:52], x12+c12)
		xor(dst[52:56], src[52:56], x13+c13)
		xor(dst[56:60], src[56:60], x14+c14)
		xor(dst[60:64], src[60:64], x15+c15)

		ctrLo += 1
		if ctrLo == 0 {
			ctrHi += 1
			// Do the quarter round that involves the high 32 bits of the counter
			fr5, fr9, fr13, fr1 = quarterRound(c5, ctrHi, c13, c1)
			if ctrHi == 0 {
				// wrap back
				panic("salsa20: internal error: counter overflow")
			}
		}
		src = src[64:]
		dst = dst[64:]
	}

	// Put the counter back after we've done all full blocks
	binary.LittleEndian.PutUint32(nonce[8:12], ctrLo)
	binary.LittleEndian.PutUint32(nonce[12:16], ctrHi)
	return
}

// genericXORKeyStream is the generic implementation of XORKeyStream to be used
// when no assembly implementation is available.
func genericXORKeyStream(out, in []byte, counter *[16]byte, key *[32]byte) {
	if len(out) < len(in) {
		panic("salsa20: internal error: out buffer smaller than input")
	}
	rem := len(in) % 64
	full := len(in) - rem

	if full > 0 {
		// Encrypt all full blocks
		xorKeyStreamBlocksGeneric(out, in, counter, key)
	}

	// If there is input left that doesn't make up a full block
	// we xor the keyStream with the input bytes individually
	if rem > 0 && rem < 64 { // check rem < 64 here to eliminate bounds check later in the loop
		var keyStream [64]byte
		keyStreamBlock(&keyStream, counter, key)
		in, out = in[full:full+rem], out[full:full+rem]
		for i := 0; i < rem; i++ {
			out[i] = in[i] ^ keyStream[i]
		}
	}
}
