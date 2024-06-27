package encryption

import (
	"io"
	"testing"
)

func TestOrderedKeyfiles(t *testing.T) {
}

func TestUnorderedKeyfiles(t *testing.T) {
}

func TestDuplicateKeyfiles(t *testing.T) {
}

// Test that the sizes of all keys, nonces, etc are of the expected size
func TestKeySizes(t *testing.T) {
	salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
	hkdfSalt := [32]byte{0, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	serpentIV := [16]byte{0, 2, 4, 6, 8}
	nonce := [24]byte{9, 7, 5, 3, 1}

	keys, err := NewKeys(
		"password123", // password
		[]io.Reader{}, // keyfiles
		true,          // paranoid
		true,          // ordered
		salt[:],
		hkdfSalt[:],
		serpentIV[:],
		nonce[:],
	)
	if err != nil {
		t.Fatal(err)
	}

	// test for length correctness
	if len(keys.key) != 32 {
		t.Fatal("Unexpected key length")
	}
	if len(keys.keyfileKey) != 32 {
		t.Fatal("Unexpected keyfileKey length")
	}
	if len(keys.salt) != 16 {
		t.Fatal("Unexpected salt length")
	}
	if len(keys.nonce) != 24 {
		t.Fatal("Unexpected nonce length")
	}
	if len(keys.macKey) != 32 {
		// on creation, the macKey won't be written yet
		t.Fatal("Unexpected macKey length")
	}
	if len(keys.serpentKey) != 32 {
		t.Fatal("Unexpected serpentKey length")
	}
	if len(keys.serpentIV) != 16 {
		t.Fatal("Unexpected serpentIV length")
	}
	if len(keys.keyfileKeyRef) != 32 {
		t.Fatal("Unexpected keyfileKeyRef length")
	}
	if len(keys.hkdfSalt) != 32 {
		t.Fatal("Unexpected hkdfSalt length")
	}

	// test for value matching
	if !arrMatch(keys.keyfileKey, make([]byte, 32)) {
		t.Fatal("keyfileKey did not propagate")
	}
	if !arrMatch(keys.salt, salt[:]) {
		t.Fatal("salt did not propagate")
	}
	if !arrMatch(keys.nonce, nonce[:]) {
		t.Fatal("nonce did not propagate")
	}
	if !arrMatch(keys.serpentIV, serpentIV[:]) {
		t.Fatal("serpentIV did not propagate")
	}
	if !(keys.usesKeyfiles == false) {
		t.Fatal("usesKeyfiles did not propagate")
	}
	if !(keys.orderedKeyfiles == true) {
		t.Fatal("orderedKeyfiles did not propagate")
	}
	if !arrMatch(keys.hkdfSalt, hkdfSalt[:]) {
		t.Fatal("hkdfSalt did not propagate")
	}
}
