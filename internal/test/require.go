package test

import (
	"testing"
)

// Require functions that fail the test immediately
func RequireNoError(t *testing.T, err error, msgAndArgs ...interface{}) {
	t.Helper()
	if err != nil {
		msg := formatMessage(msgAndArgs...)
		t.Fatalf("Unexpected error: %v%s", err, msg)
	}
}

func RequireNotNil(t *testing.T, value interface{}, msgAndArgs ...interface{}) {
	t.Helper()
	if isNil(value) {
		msg := formatMessage(msgAndArgs...)
		t.Fatalf("Expected not nil%s", msg)
	}
}

func RequireLen(t *testing.T, value interface{}, expectedLen int, msgAndArgs ...interface{}) {
	t.Helper()
	actualLen := getLen(value)
	if actualLen != expectedLen {
		msg := formatMessage(msgAndArgs...)
		t.Fatalf("Expected length %d, got %d%s", expectedLen, actualLen, msg)
	}
}
