package encryption

import (
	"errors"
)

const ResetNonceAt = int64(60 * (1 << 30))

var ErrRecoverable = errors.New("Data corrupted but recoverable")
var ErrCorrupted = errors.New("Data corrupted beyond repair")
var ErrIncorrectDataSize = errors.New("Data size does not match 136 byte chunks")

func xor(a, b []byte) []byte {
	c := make([]byte, len(a))
	for i, _ := range a {
		c[i] = a[i] ^ b[i]
	}
	return c
}

func arrMatch(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, _ := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
