package encryption

import (
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
	"hash"
	"io"
)

type Writer struct {
	w                  io.WriteSeeker
	mac                hash.Hash
	ec                 *EncryptionCipher
	deny               *Deniability
	rs                 *RSEncoder
	comments           string
	writtenSinceHeader int
	headerMask         []byte
}

func (w *Writer) headerLength() int {
	return 789 + 3*len(w.comments)
}

func (w *Writer) Write(p []byte) (int, error) {
	if len(w.headerMask) == 0 {
		err := w.reserveHeader()
		if err != nil {
			return 0, err
		}
	}
	data := make([]byte, len(p))
	w.ec.Encode(data, p)
	w.mac.Write(data)
	if w.rs != nil {
		data = w.rs.Encode(data)
	}
	if w.deny != nil {
		w.deny.Deny(data)
	}
	n, err := w.w.Write(data)
	w.writtenSinceHeader += n
	return len(p), err
}

func (w *Writer) reserveHeader() error {
	size := w.headerLength()
	if w.deny != nil {
		size += len(w.deny.salt) + len(w.deny.nonce)
	}
	_, err := w.w.Write(make([]byte, size))
	w.headerMask = make([]byte, w.headerLength())
	if w.deny != nil {
		w.deny.Deny(w.headerMask)
	}
	return err
}

func (w *Writer) flush() error {
	if w.rs == nil {
		return nil
	}
	data := w.rs.Flush()
	if w.deny != nil {
		w.deny.Deny(data)
	}
	n, err := w.w.Write(data)
	w.writtenSinceHeader += n
	return err
}

func (w *Writer) Close() error {
	err := w.flush()
	if err != nil {
		return err
	}

	offset := w.writtenSinceHeader + w.headerLength()
	if w.deny != nil {
		offset += len(w.deny.salt) + len(w.deny.nonce)
	}
	_, err = w.w.Seek(-int64(offset), io.SeekCurrent)
	if err != nil {
		return err
	}

	if w.deny != nil {
		data := append(w.deny.salt, w.deny.nonce...)
		_, err := w.w.Write(data)
		if err != nil {
			return err
		}
	}

	header := w.makeHeader()
	for i, _ := range header {
		header[i] ^= w.headerMask[i]
	}
	_, err = w.w.Write(header)
	return err
}

func (w *Writer) makeHeader() []byte {
	data := [][]byte{[]byte(Version)}
	data = append(data, []byte(fmt.Sprintf("%05d", len(w.comments))))
	for _, c := range []byte(w.comments) {
		data = append(data, []byte{c})
	}
	flags := []bool{
		w.ec.paranoid,
		w.ec.keys.usesKeyfiles,
		w.ec.keys.orderedKeyfiles,
		w.rs != nil,
		w.writtenSinceHeader%(1<<20) == 0,
	}
	flagBytes := make([]byte, len(flags))
	for i, f := range flags {
		if f {
			flagBytes[i] = 1
		}
	}
	data = append(data, flagBytes)
	data = append(data, w.ec.keys.salt)
	data = append(data, w.ec.keys.hkdfSalt)
	data = append(data, w.ec.keys.serpentIV)
	data = append(data, w.ec.keys.nonce)
	data = append(data, w.ec.keys.keyRef)
	data = append(data, w.ec.keys.keyfileKeyRef)
	data = append(data, w.mac.Sum(nil))

	header := make([]byte, 789+len(w.comments)*3)
	written := 0
	for _, d := range data {
		rsEncodeHeader(header[written:written+len(d)*3], d)
		written += len(d) * 3
	}
	return header
}

type EncryptionParams struct {
	Comments        string
	Password        string
	Keyfiles        []io.Reader
	ReedSolomon     bool
	IsParanoid      bool
	Writer          io.WriteSeeker
	OrderedKeyfiles bool
	Deniability     bool
}

func NewWriter(ep EncryptionParams) (*Writer, error) {
	// randomize seeds
	salt := make([]byte, 16)
	hkdfSalt := make([]byte, 32)
	serpentIV := make([]byte, 16)
	nonce := make([]byte, 24)
	rand.Read(salt)
	rand.Read(hkdfSalt)
	rand.Read(serpentIV)
	rand.Read(nonce)

	keys, err := NewKeys(
		ep.Password,
		ep.Keyfiles,
		ep.IsParanoid,
		ep.OrderedKeyfiles,
		salt,
		hkdfSalt,
		serpentIV,
		nonce,
	)
	if err != nil {
		return nil, err
	}

	var mac hash.Hash
	if ep.IsParanoid {
		mac = hmac.New(sha3.New512, keys.macKey)
	} else {
		mac, _ = blake2b.New512(keys.macKey)
	}

	ec := NewEncryptionCipher(keys, ep.IsParanoid)

	var deny *Deniability
	if ep.Deniability {
		deniabilitySalt := make([]byte, 16)
		deniabilityNonce := make([]byte, 24)
		rand.Read(deniabilitySalt)
		rand.Read(deniabilityNonce)
		deniabilityKey := argon2.IDKey([]byte(ep.Password), deniabilitySalt, 4, 1<<20, 4, 32)
		deny = NewDeniability(deniabilityKey, deniabilitySalt, deniabilityNonce)
	} else {
		deny = nil
	}

	var rs *RSEncoder
	if ep.ReedSolomon {
		rs = &RSEncoder{}
	}

	return &Writer{
		ep.Writer, mac, ec, deny, rs, ep.Comments, 0, []byte{},
	}, nil
}
