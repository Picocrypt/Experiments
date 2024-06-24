package encryption

import (
	"crypto/rand"
	"errors"
	"testing"
)

func TestRS(t *testing.T) {
	// pushing data thru the encoder at any size should work
	encoder := &RSEncoder{}
	origData := []byte{}
	encodedData := []byte{}
	for i := 0; i < 300; i++ {
		block := make([]byte, i)
		rand.Read(block)
		origData = append(origData, block...)
		encodedData = append(encodedData, encoder.Encode(block)...)
	}
	encodedData = append(encodedData, encoder.Flush()...)

	// sanity check the size of encodedData
	chunks := len(origData)/128 + 1
	if len(encodedData) != chunks*136 {
		t.Fatal("Encoded wrong number of chunks")
	}

	// decoding the encoded data should work without error
	decoder := &RSDecoder{}
	decodedData := []byte{}
	idx := 0
	for i := 0; i < 300; i++ {
		data := encodedData[idx : idx+i]
		d, err := decoder.Decode(data)
		if err != nil {
			t.Fatal(err)
		}
		decodedData = append(decodedData, d...)
		idx += i
	}
	// read the remaining data in
	d, err := decoder.Decode(encodedData[idx:])
	if err != nil {
		t.Fatal(err)
	}
	decodedData = append(decodedData, d...)
	// flush the decoder to strip the padded bits
	d, err = decoder.Flush()
	if err != nil {
		t.Fatal(err)
	}
	decodedData = append(decodedData, d...)

	if !arrMatch(origData, decodedData) {
		t.Fatal("Original data differs from decoded data")
	}

	// a small error should be recoverable
	damagedData := make([]byte, len(origData))
	damagedData[5] = damagedData[5] + 1
	decoder = &RSDecoder{}
	_, err = decoder.Decode(damagedData)
	if !errors.Is(err, ErrRecoverable) {
		t.Fatal(err)
	}

	// a large error is irrecoverable
	rand.Read(damagedData[5:100])
	_, err = decoder.Decode(damagedData)
	if !errors.Is(err, ErrCorrupted) {
		t.Fatal(err)
	}
}
