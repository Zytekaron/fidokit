package utils

import (
	"crypto/rand"
	"encoding/hex"
)

func RandomID() string {
	buf := make([]byte, 8)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

func RandomBytes(n int) []byte {
	buf := make([]byte, n)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return buf
}

//func SecureZero(b []byte) {
//	for i := range b {
//		b[i] = 0
//	}
//
//	// Prevent compiler from optimizing away the zeroing.
//	_ = subtle.ConstantTimeByteEq(b[0], 0)
//}
