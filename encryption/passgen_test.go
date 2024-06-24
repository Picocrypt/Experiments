package encryption

import (
	"bytes"
	"testing"
)

func TestGenKeyfileLength(t *testing.T) {
	for i := 0; i < 25; i++ {
		size := 1 << i
		k := new(bytes.Buffer)
		err := GenKeyfile(size, k)
		if err != nil {
			t.Fatal("GenKeyfile failed")
		}
		if k.Len() != size {
			t.Fatal("GenKeyfile made wrong size file")
		}
	}
}

func TestGenKeyfileUnique(t *testing.T) {
	// For a 10 byte array, the odds of of randomly matching keyfiles should
	// be 1 in 256^10
	size := 10

	keyfile1 := new(bytes.Buffer)
	err := GenKeyfile(size, keyfile1)
	if err != nil {
		t.Fatal("GenKeyfile failed")
	}

	keyfile2 := new(bytes.Buffer)
	err = GenKeyfile(size, keyfile2)
	if err != nil {
		t.Fatal("GenKeyfile failed")
	}

	are_unique := false
	for i := 0; i < size; i++ {
		b1, _ := keyfile1.ReadByte()
		b2, _ := keyfile2.ReadByte()
		if b1 != b2 {
			are_unique = true
			break
		}
	}
	if !are_unique {
		t.Fatal("Generated keyfiles match")
	}
}

func TestGenPasswordLength(t *testing.T) {
	for i := 1; i < 100; i++ {
		password := GenPassword(i, true, true, true, true)
		if len(password) != i {
			t.Fatal("Incorrect password length")
		}
	}
}

func TestGenPasswordUnique(t *testing.T) {
	for i := 0; i < 100; i++ {
		passwordA := GenPassword(10, true, true, true, true)
		passwordB := GenPassword(10, true, true, true, true)
		if passwordA == passwordB {
			t.Fatal("Randomly generated passwords match")
		}
	}
}
