package encryption

import (
	"testing"
)

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
