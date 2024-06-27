package encryption

import (
	"crypto/cipher"
	"github.com/HACKERALERT/serpent"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/sha3"
)

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

type EncryptionCipher struct {
	paranoid     bool
	chacha       *chacha20.Cipher
	serpentBlock cipher.Block
	serpent      cipher.Stream
	keys         *Keys
	counter      int64
}

func (ec *EncryptionCipher) Encode(dst, src []byte) {
	i := int64(0)
	for i < int64(len(src)) {
		j := min(int64(len(src))-i, ResetNonceAt-ec.counter)
		ec.chacha.XORKeyStream(dst[i:i+j], src[i:i+j])
		if ec.paranoid {
			ec.serpent.XORKeyStream(dst[i:i+j], dst[i:i+j])
		}
		ec.updateCounter(j)
		i += j
	}
}

func (ec *EncryptionCipher) updateCounter(length int64) {
	ec.counter += length
	if ec.counter < ResetNonceAt {
		return
	}
	nonce := make([]byte, 24)
	ec.keys.hkdf.Read(nonce)
	ec.chacha, _ = chacha20.NewUnauthenticatedCipher(ec.keys.key, ec.keys.nonce)
	serpentIV := make([]byte, 16)
	ec.keys.hkdf.Read(serpentIV)
	ec.serpent = cipher.NewCTR(ec.serpentBlock, serpentIV)
	ec.counter = 0
}

func NewEncryptionCipher(keys *Keys, paranoid bool) *EncryptionCipher {
	chacha, _ := chacha20.NewUnauthenticatedCipher(keys.key, keys.nonce)
	sb, _ := serpent.NewCipher(keys.serpentKey)
	s := cipher.NewCTR(sb, keys.serpentIV)
	return &EncryptionCipher{paranoid, chacha, sb, s, keys, 0}
}

type Deniability struct {
	key       []byte
	salt      []byte
	nonce     []byte
	liveNonce []byte
	chacha    *chacha20.Cipher
	resetAt   int64
	counter   int64
}

func (deny *Deniability) Deny(p []byte) {
	i := int64(0)
	for i < int64(len(p)) {
		j := min(int64(len(p))-i, ResetNonceAt-deny.counter)
		deny.chacha.XORKeyStream(p[i:i+j], p[i:i+j])
		deny.updateCounter(j)
		i += j
	}
}

func (deny *Deniability) updateCounter(length int64) {
	deny.counter += length
	if deny.counter < ResetNonceAt {
		return
	}
	tmp := sha3.New256()
	tmp.Write(deny.liveNonce)
	deny.liveNonce = tmp.Sum(nil)[:24]
	deny.chacha, _ = chacha20.NewUnauthenticatedCipher(deny.key, deny.liveNonce)
	deny.counter = 0
}

func NewDeniability(key, salt, nonce []byte) *Deniability {
	chacha, _ := chacha20.NewUnauthenticatedCipher(key, nonce)
	return &Deniability{key, salt, nonce, nonce, chacha, 60 * (1 << 20), 0}
}
