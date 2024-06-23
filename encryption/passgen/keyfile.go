package encryption

import (
	"crypto/rand"
	"github.com/pkg/errors"
	"io"
)

func GenKeyfile(length int, w io.Writer) error {
	// generate no more than 1 MiB of data at once to limit memory usage
	// for large keyfiles
	for length > 0 {
		size := length
		if size > (1 << 20) {
			size = 1 << 20
		}
		tmp := make([]byte, size)
		rand.Read(tmp)
		_, err := w.Write(tmp)
		if err != nil {
			return errors.Wrap(err, "Filed to write keyfile")
		}
		length -= size
	}
	return nil
}
