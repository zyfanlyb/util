package common

import (
	"time"
	"strconv"
)

func StringToDuration(s string) time.Duration {
	if s == "" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		panic(s + " 无法转换为 duration")
	}
	return d
}

func StringToInt(s string) int {
	if s == "" {
		return 0
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		panic(s + " 无法转换为 int")
	}
	return i
}