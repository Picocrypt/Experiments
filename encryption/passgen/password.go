package encryption

import (
	"crypto/rand"
	"math/big"
)

func GenPassword(length int, upper, lower, number, symbol bool) string {
	chars := ""
	if upper {
		chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if lower {
		chars += "abcdefghijklmnopqrstuvwxyz"
	}
	if number {
		chars += "1234567890"
	}
	if symbol {
		chars += "-=_+!@#$^&()?<>"
	}

	tmp := make([]byte, length)
	for i := 0; i < length; i++ {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		tmp[i] = chars[j.Int64()]
	}
	return string(tmp)
}
