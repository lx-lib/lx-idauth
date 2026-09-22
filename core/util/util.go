package util

import (
	"strconv"
	"strings"
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

func CloneStr(s string) string {
	return strings.Clone(s)
}

func CloneStrPtr(s *string) *string {
	if s == nil {
		return nil
	}

	clone := strings.Clone(*s)
	return &clone
}

func CloneTimePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}

	clone := *t
	return &clone
}
