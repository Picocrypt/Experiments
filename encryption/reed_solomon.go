package encryption

import (
	"errors"
	"github.com/HACKERALERT/infectious"
)

// Creating FEC objects is slow, so it is not feasible to generate one on
// the fly each call. The objects are stateless, so it is safe to generate
// one for each input/output size and reuse it as needed.
var fecs = make(map[[2]int]*infectious.FEC)

// RSEncode copies src to dst while adding Reed Solomon parity bytes.
// The length of dst must be at least the length of src, and the entire dst slice
// will be filled.
func RSEncode(dst, src []byte) {
	size := [2]int{len(src), len(dst)}
	fec, _ := fecs[size]
	if fec == nil {
		fec, _ = infectious.NewFEC(size[0], size[1])
		fecs[size] = fec
	}
	fec.Encode(src, func(s infectious.Share) { dst[s.Number] = s.Data[0] })
}

// RSDecode copies src to dst while decoding the Reed Solomon parity bytes.
// The length of dst must be at most the length of dst.
// Returning ErrDamaged indicates that the src data is partially corrupted, but
// fully recoverable using the parity bytes.
// Returning ErrCorrupted indicates that the src data is too corrupted to repair.
// If this happens, the first len(dst) bytes from src are copied to dst as a best
// guess of the decoded data.
func RSDecode(dst, src []byte) error {
	// Encoding is much faster than decoding. Try re-encoding the original
	// bytes and if the result matches, there must have been no corruption.
	recoded := make([]byte, len(src))
	RSEncode(recoded, src[:len(dst)])
	if arrMatch(recoded, src) {
		copy(dst, src[:len(dst)])
		return nil
	}
	// Corruption detected - try to recover
	size := [2]int{len(dst), len(src)}
	fec, _ := fecs[size]
	if fec == nil {
		fec, _ = infectious.NewFEC(size[0], size[1])
		fecs[size] = fec
	}
	tmp := make([]infectious.Share, fec.Total())
	for i := 0; i < fec.Total(); i++ {
		tmp[i].Number = i
		tmp[i].Data = append(tmp[i].Data, src[i])
	}
	res, err := fec.Decode(nil, tmp)
	if err == nil {
		copy(dst, res)
		return ErrRecoverable
	}
	// Fully corrupted - use a best guess
	copy(dst, src[:len(dst)])
	return ErrCorrupted
}


// RSBodyEncoder manages adding ReedSolomon encoding to the input data.
// When enabled, Picocrypt encodes every 128 byte chunk of data into a 136 byte
// chunk, adding 8 parity bytes. RSBodyEncoder handles state management of the
// chunking and encoding.
type RSBodyEncoder struct {
	buffer []byte
}

// Encode adds parity bytes to a stream of data.
// The data is chunked every 128 bytes. To each chunk is added 8 parity bytes.
// Then the chunks are recombined and output at once. Data that does not fill a
// chunk exactly is stored internally, and will be added to the beginning of the
// next call to Encode. To finish processing internally stored data, see
// BodyEncoder.Flush.
func (r *RSBodyEncoder) Encode(data []byte) []byte {
	r.buffer = append(r.buffer, data...)
	nChunks := len(r.buffer) / 128
	rsData := make([]byte, nChunks*136)
	for i := 0; i < nChunks; i++ {
		RSEncode(rsData[i*136:(i+1)*136], r.buffer[i*128:(i+1)*128])
	}
	r.buffer = r.buffer[nChunks*128:]
	return rsData
}

// Flush adds padding and encryption to the remaining partial chunk.
// Calls to Encode will leave 0 to 127 bytes of data stored internally. Flush will
// pad that data to 128 bytes following PKCS#7 and then add 8 parity bytes. Flush
// should only be called once per data stream, and must be called after all calls
// to Encode are complete.
func (r *RSBodyEncoder) Flush() []byte {
	padding := make([]byte, 128-len(r.buffer))
	for i := range padding {
		padding[i] = byte(128 - len(r.buffer))
	}
	dst := make([]byte, 136)
	RSEncode(dst, append(r.buffer, padding...))
	return dst
}

// RSBodyDecoder decodes data that has been encoded by BodyEncoder.
type RSBodyDecoder struct {
	buffer []byte
}

// Decode recovers the original data from a possibly corrupted data stream.
// The encoded data is parsed every 136 bytes. The original 128 bytes (or best
// guess) is recovered, then the chunks are recombined into one and returned.
// Data that does not fill a chunk is stored interally, and will be added to the
// beginning of the next call to Decode. To finish processing internally stored
// data, see RSBodyDecoder.Flush.
// 
// Returning ErrDamaged indicates that the data is partially corrupted, but fully
// recoverable using the parity bytes. Returning ErrCorrupted indicates that the 
// data is too corrupted to repair. If this happens, the first 128 bytes from each
// chunk are returned as a best guess of the decoded data.
func (r *RSBodyDecoder) Decode(data []byte) ([]byte, error) {
	r.buffer = append(r.buffer, data...)
	var decodeErr error
	nChunks := len(r.buffer) / 136
	// The last chunk might be padded, so keep it in the buffer for Flush 
	if ((len(r.buffer) % 136) == 0) && (nChunks > 0) {
		nChunks -= 1
	}
	rsData := make([]byte, nChunks*128)
	for i := 0; i < nChunks; i++ {
		src := r.buffer[i*136 : (i+1)*136]
		dst := rsData[i*128 : (i+1)*128]
		err := RSDecode(dst, src)
		if errors.Is(err, ErrCorrupted) {
			decodeErr = err
		} else if decodeErr == nil {
			decodeErr = err
		}
	}
	r.buffer = r.buffer[nChunks*136:]
	return rsData, decodeErr
}

// Flush removes padding and decodes the remaining chunk.
// After all calls to Decode for a data stream are complete, calling Flush will
// decode the final chunk and remove any padding. Flush should only be called once
// per data stream.
func (r *RSBodyDecoder) Flush() ([]byte, error) {
	res := make([]byte, 128)
	err := RSDecode(res, r.buffer)
	data := r.buffer[:128-int(res[127])]
	return data, err
}
