//go:build race

package pipeline

// See race_off_test.go for why the memory matrix does not run under -race.
const raceEnabled = true
