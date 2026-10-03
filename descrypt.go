package main

import (
	"errors"
	"strings"
)

// Traditional DES-based crypt(3) — the 13-character, no-"$"-prefix hash used by
// old Linux/UNIX systems (e.g. accounts created with perl's crypt() or legacy
// SSH-account scripts). Pure Go; no dependency on libcrypt.
//
// Verified against the canonical vector crypt("rasmuslerdorf","rl") ==
// "rl.3StKT.4T8M" (see descrypt_test.go).

const cryptAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func crypt64Decode(c byte) int {
	return strings.IndexByte(cryptAlphabet, c)
}

// ---- Standard DES permutation tables (1-indexed, MSB-first) ----

var ipTable = []int{
	58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
}

var fpTable = []int{
	40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
}

var eTable = []int{
	32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
}

var pTable = []int{
	16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
	2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
}

var pc1Table = []int{
	57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
}

var pc2Table = []int{
	14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
}

var shiftTable = []int{1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}

var sBoxes = [8][64]int{
	{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
	{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
	{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
	{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
	{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
	{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
	{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
	{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
}

// permute selects bits from in (each element 0/1, MSB-first) per a 1-indexed table.
func permute(in []byte, table []int) []byte {
	out := make([]byte, len(table))
	for i, pos := range table {
		out[i] = in[pos-1]
	}
	return out
}

func keySchedule(key64 []byte) [][]byte {
	cd := permute(key64, pc1Table) // 56 bits
	c := cd[:28]
	d := cd[28:]
	subkeys := make([][]byte, 16)
	for i := 0; i < 16; i++ {
		c = rotl(c, shiftTable[i])
		d = rotl(d, shiftTable[i])
		combined := append(append([]byte{}, c...), d...)
		subkeys[i] = permute(combined, pc2Table) // 48 bits
	}
	return subkeys
}

func rotl(b []byte, n int) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[(i+n)%len(b)]
	}
	return out
}

// feistel computes f(R, K) with the salt-perturbed E expansion.
func feistel(r []byte, k []byte, saltMask [24]bool) []byte {
	e := permute(r, eTable) // 48 bits
	// Salt: for i in 0..23, if saltMask[i] swap E-output bits i and i+24.
	for i := 0; i < 24; i++ {
		if saltMask[i] {
			e[i], e[i+24] = e[i+24], e[i]
		}
	}
	x := make([]byte, 48)
	for i := range x {
		x[i] = e[i] ^ k[i]
	}
	out := make([]byte, 32)
	for box := 0; box < 8; box++ {
		off := box * 6
		row := int(x[off])<<1 | int(x[off+5])
		col := int(x[off+1])<<3 | int(x[off+2])<<2 | int(x[off+3])<<1 | int(x[off+4])
		val := sBoxes[box][row*16+col]
		for bit := 0; bit < 4; bit++ {
			out[box*4+bit] = byte((val >> (3 - bit)) & 1)
		}
	}
	return permute(out, pTable)
}

func desEncryptBlock(block []byte, subkeys [][]byte, saltMask [24]bool) []byte {
	ip := permute(block, ipTable)
	l := ip[:32]
	r := ip[32:]
	for i := 0; i < 16; i++ {
		f := feistel(r, subkeys[i], saltMask)
		newR := make([]byte, 32)
		for j := 0; j < 32; j++ {
			newR[j] = l[j] ^ f[j]
		}
		l = r
		r = newR
	}
	pre := append(append([]byte{}, r...), l...) // R16 L16
	return permute(pre, fpTable)
}

// desCrypt implements the traditional 13-char DES crypt. setting supplies the
// 2-char salt (its first two characters).
func desCrypt(password, setting string) (string, error) {
	if len(setting) < 2 {
		return "", errors.New("descrypt: salt too short")
	}
	s0 := crypt64Decode(setting[0])
	s1 := crypt64Decode(setting[1])
	if s0 < 0 || s1 < 0 {
		return "", errors.New("descrypt: bad salt characters")
	}
	salt := s0 | (s1 << 6)
	var saltMask [24]bool
	for i := 0; i < 24; i++ {
		if (salt>>i)&1 == 1 {
			saltMask[i] = true
		}
	}

	// Key: first 8 bytes of the password, each char<<1 forms a key byte.
	key64 := make([]byte, 64)
	for i := 0; i < 8; i++ {
		var c byte
		if i < len(password) {
			c = password[i]
		}
		kb := c << 1
		for bit := 0; bit < 8; bit++ {
			key64[i*8+bit] = (kb >> (7 - bit)) & 1
		}
	}
	subkeys := keySchedule(key64)

	block := make([]byte, 64) // all zeros
	for iter := 0; iter < 25; iter++ {
		block = desEncryptBlock(block, subkeys, saltMask)
	}

	return string(setting[0]) + string(setting[1]) + encodeDESOutput(block), nil
}

// encodeDESOutput packs the 64-bit result (MSB-first bit array) into 11
// crypt-base64 characters: eleven 6-bit groups read most-significant-bit first,
// the last group zero-padded to 6 bits.
func encodeDESOutput(block []byte) string {
	out := make([]byte, 0, 11)
	for j := 0; j < 11; j++ {
		v := 0
		for k := 0; k < 6; k++ {
			idx := j*6 + k
			bit := 0
			if idx < len(block) {
				bit = int(block[idx])
			}
			v = (v << 1) | bit
		}
		out = append(out, cryptAlphabet[v])
	}
	return string(out)
}
