package encryption

import (
	"crypto/rand"
	"io"
	"math/big"
)

func GenKeyfile(length int, w io.Writer) error {
	for length > 0 {
		size := length
		if size > (1 << 20) { // limit to 1 MiB at a time for memory
			size = 1 << 20
		}
		tmp := make([]byte, size)
		rand.Read(tmp)
		_, err := w.Write(tmp)
		if err != nil {
			return err
		}
		length -= size
	}
	return nil
}

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
