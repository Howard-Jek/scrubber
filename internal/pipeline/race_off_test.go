//go:build !race

package pipeline

// raceEnabled reports whether the binary was built with -race. The heap
// measurements in memory_test.go are meaningless under the race detector — its
// shadow memory and redzones inflate every allocation — and instrumenting a matrix
// that deliberately allocates hundreds of MiB pushes the package past the default
// go test timeout, which reads as a failure rather than as "this test does not
// apply here". So the matrix declines to run rather than report a number that
// cannot be compared with the production one.
const raceEnabled = false
