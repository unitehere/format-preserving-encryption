package fpe

import (
	"log"
	"testing"
)
// Utility Functions for Assertions

func assertExpectedResult(t *testing.T, expected, actual string) {
	if expected != actual {
		t.Errorf("Expected result of \"%s\", but it was \"%s\" instead.", expected, actual)
	}
}

func assertError(t *testing.T, err error) {
	if err == nil {
		t.Errorf("Expected an error but received none.")
	}
}

func assertNoError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("Test failed as an unexpected error occured.")
		log.Fatal(err)
	}
}
