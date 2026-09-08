package archive

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"math/rand"
	"testing"
	"time"

	"github.com/howard/scrubber/internal/spill"
)

// A packfile is attacker-controlled binary input: it arrives inside an upload from
// whoever is using the service. ReadPack must therefore never hang, never allocate
// without bound, and never panic, whatever the bytes say — the guarantee the rest of
// the pipeline already makes for zip and tar.
//
// These are the shapes worth being explicit about rather than trusting to fuzzing.

func packPrefix(objects uint32) []byte {
	var b bytes.Buffer
	b.WriteString("PACK")
	binary.Write(&b, binary.BigEndian, uint32(2))
	binary.Write(&b, binary.BigEndian, objects)
	return b.Bytes()
}

func TestReadPackSurvivesHostileInput(t *testing.T) {
	huge := packPrefix(0xFFFFFFFF) // claims four billion objects

	// A continuation-bit run: every byte says "more size bits follow", so the shift
	// in readPackObjHeader grows without limit. Must terminate on the input ending
	// rather than spinning.
	contRun := append(packPrefix(1), bytes.Repeat([]byte{0xFF}, 4096)...)

	// A header that promises a large object and then stops.
	truncated := append(packPrefix(1), 0xB0, 0xFF, 0xFF, 0x7F)

	// Valid header, garbage where the zlib stream should be.
	badZlib := append(packPrefix(1), 0x30, 'n', 'o', 't', 'z', 'l', 'i', 'b')

	// A small object declaring a vast size: the guard must be the budget, not the
	// declared number.
	var lying bytes.Buffer
	lying.Write(packPrefix(1))
	lying.Write([]byte{0xB0, 0xFF, 0xFF, 0xFF, 0x7F}) // blob, enormous declared size
	zw := zlib.NewWriter(&lying)
	zw.Write([]byte("tiny"))
	zw.Close()

	// Random bytes behind a valid magic.
	rng := rand.New(rand.NewSource(1))
	noise := packPrefix(64)
	junk := make([]byte, 8192)
	rng.Read(junk)
	noise = append(noise, junk...)

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"claims four billion objects", huge},
		{"unterminated size varint", contRun},
		{"truncated after header", truncated},
		{"not a zlib stream", badZlib},
		{"declared size is a lie", lying.Bytes()},
		{"random noise", noise},
		{"header only", packPrefix(1)},
		{"empty", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("panic on hostile input: %v", r)
					}
				}()
				objs, err := ReadPack(bytes.NewReader(tc.data), 1<<20, 1000, spill.DefaultPolicy)
				ClosePack(objs)
				_ = err // an error is a fine outcome; hanging or panicking is not
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("ReadPack did not terminate on hostile input")
			}
		})
	}
}

// objHeader encodes the variable-length type/size header, so a test exercises the
// guard it means to rather than being rejected by a malformed header first.
func objHeader(typ byte, size int) []byte {
	var out []byte
	b := byte(typ<<4) | byte(size&0x0f)
	size >>= 4
	for size > 0 {
		out = append(out, b|0x80)
		b = byte(size & 0x7f)
		size >>= 7
	}
	return append(out, b)
}

// TestReadPackRespectsBudget: the caller's byte ceiling must bound what a pack can
// cost, whatever its object headers declare. Without it one crafted pack fills the
// pod's scratch volume, which evicts it as surely as an OOM and leaves no report.
func TestReadPackRespectsBudget(t *testing.T) {
	const content = 1 << 20
	var buf bytes.Buffer
	buf.Write(packPrefix(1))
	buf.Write(objHeader(3, content))
	zw := zlib.NewWriter(&buf)
	zw.Write(bytes.Repeat([]byte("A"), content))
	zw.Close()

	// Sanity: the same pack under a generous budget must read cleanly, or the
	// refusal below would prove nothing.
	objs, err := ReadPack(bytes.NewReader(buf.Bytes()), 1<<22, 1000, spill.DefaultPolicy)
	if err != nil {
		t.Fatalf("well-formed pack rejected under a generous budget: %v", err)
	}
	if len(objs) != 1 || objs[0].Body.Size() != content {
		t.Fatalf("decoded %d objects, first size %v; want 1 of %d",
			len(objs), objs[0].Body.Size(), content)
	}
	ClosePack(objs)

	objs, err = ReadPack(bytes.NewReader(buf.Bytes()), 1024, 1000, spill.DefaultPolicy)
	ClosePack(objs)
	if err != ErrTooLarge {
		t.Errorf("err = %v, want ErrTooLarge: a 1 MiB object was admitted under a "+
			"1 KiB budget", err)
	}
}

// TestReadPackRespectsObjectCap: maxObjects must bound the walk regardless of what
// the header claims.
func TestReadPackRespectsObjectCap(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(packPrefix(100))
	for i := 0; i < 100; i++ {
		buf.Write([]byte{0x34}) // blob, 4 bytes
		zw := zlib.NewWriter(&buf)
		zw.Write([]byte("aaaa"))
		zw.Close()
	}
	objs, err := ReadPack(bytes.NewReader(buf.Bytes()), 1<<20, 10, spill.DefaultPolicy)
	ClosePack(objs)
	if err != ErrTooManyMembers {
		t.Errorf("err = %v, want ErrTooManyMembers once the cap is passed", err)
	}
}
