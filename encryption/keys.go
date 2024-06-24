package encryption

import (
	"errors"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
	"io"
)

var ErrDuplicateKeyfiles = errors.New("Duplicate keyfiles detected")

type Keys struct {
	key             []byte
	keyfileKey      []byte
	salt            []byte
	nonce           []byte
	macKey          []byte
	serpentKey      []byte
	serpentIV       []byte
	usesKeyfiles    bool
	orderedKeyfiles bool
	hkdf            io.Reader
	keyfileKeyRef   []byte
	keyRef          []byte
	hkdfSalt        []byte
}

func genKeyfileKey(ordered bool, kf []io.Reader) ([]byte, error) {
	if len(kf) == 0 {
		return make([]byte, 32), nil
	}

	hashes := make([][]byte, len(kf))
	tmp := sha3.New256()
	for i, k := range kf {
		for {
			// read 1 MiB at a time to limit memory usage
			data := make([]byte, 1<<20)
			size, err := k.Read(data)
			tmp.Write(data[:size])
			if errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				return []byte{}, err
			}
		}
		hashes[i] = tmp.Sum(nil)
		if !ordered {
			tmp.Reset()
		}
	}

	if ordered {
		return tmp.Sum(nil), nil
	}

	kfKey := hashes[0]
	for _, h := range hashes[1:] {
		kfKey = xor(kfKey, h)
	}
	var err error
	for i, h1 := range hashes {
		for _, h2 := range hashes[i:] {
			if arrMatch(h1, h2) {
				err = ErrDuplicateKeyfiles
			}
		}
	}
	return kfKey, err
}

func genPasswordKey(password string, salt []byte, isParanoid bool) []byte {
	if isParanoid {
		return argon2.IDKey([]byte(password), salt, 8, 1<<20, 8, 32)
	}
	return argon2.IDKey([]byte(password), salt, 4, 1<<20, 4, 32)
}

func NewKeys(
	password string,
	keyfiles []io.Reader,
	isParanoid bool,
	areKeyfilesOrdered bool,
	salt []byte,
	hkdfSalt []byte,
	serpentIV []byte,
	nonce []byte,
) (*Keys, error) {
	kfKey, err := genKeyfileKey(areKeyfilesOrdered, keyfiles)
	if err != nil && !errors.Is(err, ErrDuplicateKeyfiles) {
		return nil, err
	}
	pwKey := genPasswordKey(password, salt, isParanoid)
	key := xor(kfKey, pwKey)
	tmp := sha3.New512()
	tmp.Write(key)
	keyRef := tmp.Sum(nil)
	tmp = sha3.New256()
	tmp.Write(kfKey)
	kfKeyRef := tmp.Sum(nil)

	hkdf := hkdf.New(sha3.New256, key, hkdfSalt, nil)
	macKey := make([]byte, 32)
	hkdf.Read(macKey)
	serpentKey := make([]byte, 32)
	hkdf.Read(serpentKey)

	return &Keys{
		key,
		kfKey,
		salt,
		nonce,
		macKey,
		serpentKey,
		serpentIV,
		len(keyfiles) > 0,
		areKeyfilesOrdered,
		hkdf,
		kfKeyRef,
		keyRef,
		hkdfSalt,
	}, nil
}
