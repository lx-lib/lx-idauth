package util

import (
	"strconv"
	"time"
)

func PtrString(v string) *string {
	if v == "" {
		return nil
	}

	return &v
}

func PtrTime(v time.Time) *time.Time {
	return &v
}

func PtrBool(v bool) *bool {
	return &v
}

func DerefString(v *string) string {
	if v == nil {
		return ""
	}

	return *v
}

func StrToPtrInt(v string) *int {
	if v == "" {
		return nil
	}
	p, err := strconv.Atoi(v)
	if err != nil {
		return nil
	}

	return &p
}
