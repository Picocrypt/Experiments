package encryption

import (
	"errors"
	"github.com/HACKERALERT/infectious"
)

func rsEncode(dst, src []byte) {
	rs, _ := infectious.NewFEC(len(src), len(dst))
	rs.Encode(src, func(s infectious.Share) { dst[s.Number] = s.Data[0] })
}

type RSEncoder struct {
	buffer []byte
}

func (r *RSEncoder) Encode(data []byte) []byte {
	r.buffer = append(r.buffer, data...)
	nChunks := len(r.buffer) / 128
	rsData := make([]byte, nChunks*136)
	for i := 0; i < nChunks; i++ {
		rsEncode(rsData[i*136:(i+1)*136], r.buffer[i*128:(i+1)*128])
	}
	r.buffer = r.buffer[nChunks*128:]
	return rsData
}

func (r *RSEncoder) Flush() []byte {
	padding := make([]byte, 128-len(r.buffer))
	for i := range padding {
		padding[i] = byte(128 - len(r.buffer))
	}
	dst := make([]byte, 136)
	rsEncode(dst, append(r.buffer, padding...))
	return dst
}

func rsDecode(dst, src []byte) error {
	rs, _ := infectious.NewFEC(len(dst), len(src))
	// Encoding is much faster than decoding. Try re-encoding the original
	// bytes and if the result matches, there must have been no corruption.
	recoded := make([]byte, len(src))
	rsEncode(recoded, src[:len(dst)])
	if arrMatch(recoded, src) {
		copy(dst, src[:len(dst)])
		return nil
	}
	// Corruption detected - try to recover
	tmp := make([]infectious.Share, rs.Total())
	for i := 0; i < rs.Total(); i++ {
		tmp[i].Number = i
		tmp[i].Data = append(tmp[i].Data, src[i])
	}
	res, err := rs.Decode(nil, tmp)
	if err == nil {
		copy(dst[:], res)
		return ErrRecoverable
	}
	// Fully corrupted - use a best guess and fail
	copy(dst, src[:len(dst)])
	return ErrCorrupted
}

type RSDecoder struct {
	buffer []byte
}

func (r *RSDecoder) Decode(data []byte) ([]byte, error) {
	r.buffer = append(r.buffer, data...)
	var decodeErr error
	nChunks := len(r.buffer) / 136
	if ((len(r.buffer) % 136) == 0) && (nChunks > 0) {
		nChunks -= 1
	}
	rsData := make([]byte, nChunks*128)
	for i := 0; i < nChunks; i++ {
		src := r.buffer[i*136 : (i+1)*136]
		dst := rsData[i*128 : (i+1)*128]
		err := rsDecode(dst, src)
		if errors.Is(err, ErrCorrupted) {
			decodeErr = err
		} else if decodeErr == nil {
			decodeErr = err
		}
	}
	r.buffer = r.buffer[nChunks*136:]
	return rsData, decodeErr
}

func (r *RSDecoder) Flush() ([]byte, error) {
	res := make([]byte, 128)
	err := rsDecode(res, r.buffer)
	data := r.buffer[:128-int(res[127])]
	return data, err
}
