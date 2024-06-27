package encryption

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
	"hash"
	"io"
	"regexp"
	"strconv"
)

type Decryptor struct {
	password string
	r        io.Reader
	mac      hash.Hash
	ec       *EncryptionCipher
	deny     *Deniability
	rs       *RSBodyDecoder
	macTag   []byte

	headerMask []byte
	eof        bool
	buffer     []byte
	flushed    bool
}

func (d *Decryptor) Read(p []byte) (int, error) {
	data := []byte{}
	if !d.eof {
		data = make([]byte, len(p))
		n, err := d.r.Read(data)
		data = data[:n]
		if err == io.EOF {
			d.eof = true
		} else if err != nil {
			return 0, err
		}
	}

	var decodeErr error
	if d.deny != nil {
		d.deny.Deny(data)
	}
	if d.rs != nil && len(data) > 0 {
		data, decodeErr = d.rs.Decode(data)
	}
	if d.eof && !d.flushed && d.rs != nil {
		d.flushed = true
		flushData, err := d.rs.Flush()
		if errors.Is(err, ErrCorrupted) || decodeErr == nil {
			decodeErr = err
		}
		data = append(data, flushData...)
	}
	d.mac.Write(data)
	d.ec.Encode(data, data)
	d.buffer = append(d.buffer, data...)

	n := copy(p, d.buffer)
	d.buffer = d.buffer[n:]
	if (len(d.buffer) == 0) && d.eof {
		macTag := d.mac.Sum(nil)
		for i, m := range macTag {
			if d.macTag[i] != m {
				decodeErr = ErrCorrupted
			}
		}
		if decodeErr == nil {
			decodeErr = io.EOF
		}
	}
	return n, decodeErr
}

func readFromHeader(r io.Reader, size int, deny *Deniability) ([]byte, error) {
	if size == 0 {
		return []byte{}, nil
	}
	tmp := make([]byte, size*3)
	n, err := r.Read(tmp)
	if (n != len(tmp)) || (err != nil) {
		return []byte{}, err
	}
	if deny != nil {
		deny.Deny(tmp)
	}
	data := make([]byte, size)
	err = RSDecode(data, tmp)
	if errors.Is(err, ErrCorrupted) {
		return tmp, err
	}
	return data, err
}

var Version = "v1.99"

func NewDecryptor(
	pw string,
	kf []io.Reader,
	r io.Reader,
) (*Decryptor, error) {

	var deny *Deniability
	headerDamaged := false

	version, err := readFromHeader(r, 5, deny)
	valid, _ := regexp.Match(`^v1\.\d{2}`, []byte(version))
	if !valid {
		data := make([]byte, 40)
		copy(data, version[:15])
		r.Read(data[15:])
		key := argon2.IDKey([]byte(pw), data[:16], 4, 1<<20, 4, 32)
		deny = NewDeniability(key, data[:16], data[16:])
		fmt.Println(data)
		version, err = readFromHeader(r, 5, deny)
		valid, _ = regexp.Match(`^v1\.\d{2}`, version)
		if !valid {
			return nil, ErrCorrupted
		}
	}
	if errors.Is(err, ErrRecoverable) {
		headerDamaged = true
	}

	cLen, err := readFromHeader(r, 5, deny)
	if errors.Is(err, ErrCorrupted) {
		headerDamaged = true
		fmt.Println("Bad")
	} else {
		c, _ := strconv.Atoi(string(cLen))
		fmt.Print("Comment length: ")
		fmt.Println(c)
		for i := 0; i < c; i++ {
			readFromHeader(r, 1, deny)
		}
	}

	errs := make([]error, 10)
	components := make([][]byte, 10)
	components[2], errs[2] = readFromHeader(r, 5, deny)
	components[3], errs[3] = readFromHeader(r, 16, deny)
	components[4], errs[4] = readFromHeader(r, 32, deny)
	components[5], errs[5] = readFromHeader(r, 16, deny)
	components[6], errs[6] = readFromHeader(r, 24, deny)
	components[7], errs[7] = readFromHeader(r, 64, deny)
	components[8], errs[8] = readFromHeader(r, 32, deny)
	components[9], errs[9] = readFromHeader(r, 64, deny)

	for _, err := range errs {
		if errors.Is(err, ErrRecoverable) {
			headerDamaged = true
		} else if err != nil {
			return nil, err
		}
	}

	paranoid := components[2][0] == 1
	orderedKeyfiles := components[2][2] == 1

	keys, err := NewKeys(
		pw,
		kf,
		paranoid,
		orderedKeyfiles,
		components[3],
		components[4],
		components[5],
		components[6],
	)
	// Generate keys. Allow duplicates in case the file was encrypted before
	// catching duplicates was put in place.
	if err != nil && !errors.Is(err, ErrDuplicateKeyfiles) {
		return nil, err
	}

	var rs *RSBodyDecoder
	if components[2][3] == 1 { // reed solomon bit is set
		rs = &RSBodyDecoder{}
	}

	var mac hash.Hash
	if components[2][0] == 1 { // paranoid
		mac = hmac.New(sha3.New512, keys.macKey)
	} else {
		mac, _ = blake2b.New512(keys.macKey)
	}

	ec := NewEncryptionCipher(keys, paranoid)

	decryptor := &Decryptor{
		r:      r,
		mac:    mac,
		ec:     ec,
		deny:   deny,
		rs:     rs,
		macTag: components[9],
	}
	if headerDamaged {
		return decryptor, errors.New("Damaged header but recovered")
	}
	return decryptor, nil
}
