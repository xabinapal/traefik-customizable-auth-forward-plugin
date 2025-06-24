package test

import (
	"fmt"
	"reflect"
	"strings"
)

// Helper functions
func formatMessage(msgAndArgs ...interface{}) string {
	if len(msgAndArgs) == 0 {
		return ""
	}
	if len(msgAndArgs) == 1 {
		return fmt.Sprintf(": %v", msgAndArgs[0])
	}
	return fmt.Sprintf(": "+msgAndArgs[0].(string), msgAndArgs[1:]...)
}

func isNil(value interface{}) bool {
	if value == nil {
		return true
	}

	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func isEmpty(value interface{}) bool {
	if value == nil {
		return true
	}

	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Array, reflect.Chan, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Ptr:
		if v.IsNil() {
			return true
		}
		return isEmpty(v.Elem().Interface())
	}
	return false
}

func getLen(value interface{}) int {
	if value == nil {
		return 0
	}

	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Array, reflect.Chan, reflect.Map, reflect.Slice, reflect.String:
		return v.Len()
	}
	return 0
}

func contains(container, item interface{}) bool {
	if container == nil {
		return false
	}

	containerVal := reflect.ValueOf(container)

	switch containerVal.Kind() {
	case reflect.String:
		return strings.Contains(containerVal.String(), fmt.Sprintf("%v", item))
	case reflect.Slice, reflect.Array:
		for i := 0; i < containerVal.Len(); i++ {
			elem := containerVal.Index(i).Interface()
			if reflect.DeepEqual(elem, item) {
				return true
			}
		}
		// Special case for string slices
		if itemStr, ok := item.(string); ok {
			for i := 0; i < containerVal.Len(); i++ {
				if elemStr, ok := containerVal.Index(i).Interface().(string); ok && elemStr == itemStr {
					return true
				}
			}
		}
	case reflect.Map:
		return containerVal.MapIndex(reflect.ValueOf(item)).IsValid()
	}

	return false
}
