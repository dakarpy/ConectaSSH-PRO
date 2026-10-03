package main

import "testing"

func TestDESCryptCanonical(t *testing.T) {
	got, err := desCrypt("rasmuslerdorf", "rl")
	if err != nil {
		t.Fatal(err)
	}
	want := "rl.3StKT.4T8M"
	t.Logf("got=%q want=%q", got, want)
	if got != want {
		t.Errorf("desCrypt mismatch: got %q want %q", got, want)
	}
}
