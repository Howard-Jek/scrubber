package worker

import "io"

// transferHeartbeatBytes is how often a streaming transfer stamps progress.
// Small enough that even a crawling transfer reports inside a stall budget,
// large enough that the stamp is lost in the cost of the I/O itself.
const transferHeartbeatBytes = 8 << 20

// heartbeatWriter and heartbeatReader keep an object-storage transfer visible.
//
// Progress is stamped when a phase changes and when a file is recorded, and a
// transfer is neither: the download sits in "reading" and the upload in
// "writing", each publishing nothing from the first byte to the last. That was
// merely misleading while the stall check only logged. Once it can ABANDON an
// object, a slow-but-moving transfer is indistinguishable from a stopped one, and
// a bundle downloading at a megabyte a second on a bad day would be destroyed for
// it. TRANSFER_STALL_TIMEOUT does not cover this: it fires only on a transfer
// that has moved NO bytes at all for its window.
type heartbeatWriter struct {
	w    io.Writer
	tick func()
	n    int64
	next int64
}

func (h *heartbeatWriter) Write(p []byte) (int, error) {
	n, err := h.w.Write(p)
	h.n += int64(n)
	if h.n >= h.next {
		h.next = h.n + transferHeartbeatBytes
		h.tick()
	}
	return n, err
}

type heartbeatReader struct {
	r    io.Reader
	tick func()
	n    int64
	next int64
}

func (h *heartbeatReader) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	h.n += int64(n)
	if h.n >= h.next {
		h.next = h.n + transferHeartbeatBytes
		h.tick()
	}
	return n, err
}
