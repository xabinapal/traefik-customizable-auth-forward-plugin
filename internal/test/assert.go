package test

import (
	"reflect"
	"testing"
)

func AssertEqual(t *testing.T, expected, actual interface{}, msgAndArgs ...interface{}) {
	t.Helper()
	if !reflect.DeepEqual(expected, actual) {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("Expected %v, got %v%s", expected, actual, msg)
	}
}

func AssertNotEqual(t *testing.T, expected, actual interface{}, msgAndArgs ...interface{}) {
	t.Helper()
	if reflect.DeepEqual(expected, actual) {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("Expected %v to not equal %v%s", expected, actual, msg)
	}
}

func AssertTrue(t *testing.T, condition bool, msgAndArgs ...interface{}) {
	t.Helper()
	if !condition {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("Expected true%s", msg)
	}
}

func AssertFalse(t *testing.T, condition bool, msgAndArgs ...interface{}) {
	t.Helper()
	if condition {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("Expected false%s", msg)
	}
}

func AssertNotNil(t *testing.T, value interface{}, msgAndArgs ...interface{}) {
	t.Helper()
	if isNil(value) {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("Expected not nil%s", msg)
	}
}

func AssertNil(t *testing.T, value interface{}, msgAndArgs ...interface{}) {
	t.Helper()
	if !isNil(value) {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("Expected nil, got %v%s", value, msg)
	}
}

func AssertEmpty(t *testing.T, value interface{}, msgAndArgs ...interface{}) {
	t.Helper()
	if !isEmpty(value) {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("Expected empty, got %v%s", value, msg)
	}
}

func AssertLen(t *testing.T, value interface{}, expectedLen int, msgAndArgs ...interface{}) {
	t.Helper()
	actualLen := getLen(value)
	if actualLen != expectedLen {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("Expected length %d, got %d%s", expectedLen, actualLen, msg)
	}
}

func AssertContains(t *testing.T, container, item interface{}, msgAndArgs ...interface{}) {
	t.Helper()
	if !contains(container, item) {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("Expected %v to contain %v%s", container, item, msg)
	}
}

func AssertNotContains(t *testing.T, container, item interface{}, msgAndArgs ...interface{}) {
	t.Helper()
	if contains(container, item) {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("Expected %v to not contain %v%s", container, item, msg)
	}
}

func AssertError(t *testing.T, err error, msgAndArgs ...interface{}) {
	t.Helper()
	if err == nil {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("Expected error%s", msg)
	}
}
