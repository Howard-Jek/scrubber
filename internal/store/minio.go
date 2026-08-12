// Package store wraps the MinIO/S3 object operations the worker needs: list new
// input objects, fetch bytes, put results, and mark an input processed (move or
// delete). It is deliberately small and mockable via the ObjectStore interface.
package store

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// ErrTooLarge is returned by GetLimited when an object exceeds the byte cap. The
// worker treats it as a graceful skip so an oversized object never OOMs the pod.
var ErrTooLarge = errors.New("object exceeds size limit")

// Object is a listed object's identity.
type Object struct {
	Key          string
	Size         int64
	LastModified time.Time
}

// ObjectStore is the subset of behavior the worker depends on (mockable in tests).
type ObjectStore interface {
	List(ctx context.Context, bucket, prefix string) ([]Object, error)
	Get(ctx context.Context, bucket, key string) ([]byte, error)
	GetLimited(ctx context.Context, bucket, key string, max int64) ([]byte, error)
	Exists(ctx context.Context, bucket, key string) (bool, []byte, error)
	Put(ctx context.Context, bucket, key string, data []byte, contentType string) error
	// PutStream uploads from a reader, so a result assembled on scratch storage is
	// never materialised on the heap just to be sent. size may be -1 for unknown,
	// which switches the client to multipart streaming.
	PutStream(ctx context.Context, bucket, key string, r io.Reader, size int64, contentType string) error
	// GetLimitedTo streams an object into w, reading at most max bytes and returning
	// ErrTooLarge past that. It is GetLimited without the intermediate []byte.
	GetLimitedTo(ctx context.Context, w io.Writer, bucket, key string, max int64) (int64, error)
	Move(ctx context.Context, bucket, srcKey, dstKey string) error
	Delete(ctx context.Context, bucket, key string) error
}

// Config configures the MinIO client.
type Config struct {
	Endpoint  string // host:port, no scheme
	AccessKey string
	SecretKey string
	UseTLS    bool
	CACert    string // optional path to a CA cert for the MinIO endpoint
	Region    string
	// PublicEndpoint (host[:port]) rewrites the host of presigned URLs so a browser
	// can reach MinIO even when the in-cluster endpoint differs. Empty = use Endpoint.
	PublicEndpoint string
	PublicTLS      bool
	// StallTimeout abandons a transfer that has moved no bytes for this long.
	// Zero uses defaultStallTimeout; negative disables the guard, which restores
	// the unbounded wait and should only be used to prove one is happening.
	StallTimeout time.Duration
}

// Client is the concrete MinIO-backed ObjectStore.
type Client struct {
	mc      *minio.Client // in-cluster endpoint, used for all object operations
	presign *minio.Client // signs presigned URLs against the browser-reachable host
	stall   time.Duration // per-transfer inactivity budget; <=0 disables
}

// guard derives a cancellable context for one transfer and arms a stall watch on
// it. Callers must defer both returned funcs: cancel releases the context, and
// stop ends the watch and reports whether it had already tripped.
func (c *Client) guard(ctx context.Context) (context.Context, *stallGuard, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	return ctx, newStallGuard(c.stall, cancel), cancel
}

// stalledOr maps a transfer error onto ErrStalled when the guard was what ended
// it, and leaves every other failure untouched.
func stalledOr(g *stallGuard, err error) error {
	if g.stop() {
		return fmt.Errorf("%w after %d bytes: nothing moved for the stall timeout: %w",
			ErrStalled, g.bytesMoved(), err)
	}
	return err
}

// opCtx bounds a metadata call — stat, copy, delete, bucket check.
//
// These move no payload, so there is no progress to watch and a flat deadline is
// the right shape. They still need one: they run on the same long-lived context
// as everything else, and a stat that never returns blocks the single consumer
// exactly as thoroughly as a stalled body read. Deriving the bound from the
// stall timeout keeps one knob rather than two.
func (c *Client) opCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.stall <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.stall)
}

// listCtx bounds a listing, which unlike the other metadata calls legitimately
// scales with the bucket: it paginates, and the input bucket includes processed/.
// Given a much longer budget for that reason, but still a finite one.
func (c *Client) listCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.stall <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.stall*listTimeoutFactor)
}

// listTimeoutFactor is how much longer a listing may take than a point operation.
const listTimeoutFactor = 10

// New builds a MinIO client from Config. When PublicEndpoint is set, a second
// client is created bound to that host purely for presigning: SigV4 signs the host
// header, so a presigned URL must be *signed* against the host the browser will use,
// not merely rewritten afterwards (rewriting breaks the signature).
func New(cfg Config) (*Client, error) {
	creds := credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, "")
	// Pin a region so presigning never needs a live GetBucketLocation call — the
	// presign client is bound to the public host, which may be unreachable from
	// inside the pod. MinIO's default region is us-east-1.
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	opts := &minio.Options{Creds: creds, Secure: cfg.UseTLS, Region: region}
	if cfg.UseTLS && cfg.CACert != "" {
		pool, err := caPool(cfg.CACert)
		if err != nil {
			return nil, err
		}
		opts.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}
	mc, err := minio.New(cfg.Endpoint, opts)
	if err != nil {
		return nil, fmt.Errorf("minio client: %w", err)
	}

	presign := mc
	if cfg.PublicEndpoint != "" {
		popts := &minio.Options{Creds: creds, Secure: cfg.PublicTLS, Region: region}
		if cfg.PublicTLS && cfg.CACert != "" {
			popts.Transport = opts.Transport
		}
		presign, err = minio.New(cfg.PublicEndpoint, popts)
		if err != nil {
			return nil, fmt.Errorf("minio presign client: %w", err)
		}
	}
	stall := cfg.StallTimeout
	if stall == 0 {
		stall = defaultStallTimeout
	}
	return &Client{mc: mc, presign: presign, stall: stall}, nil
}

// PresignPut returns a presigned URL a browser can PUT an object to directly.
func (c *Client) PresignPut(ctx context.Context, bucket, key string, expiry time.Duration) (string, error) {
	u, err := c.presign.PresignedPutObject(ctx, bucket, key, expiry)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// PresignGet returns a presigned URL a browser can GET an object from directly.
func (c *Client) PresignGet(ctx context.Context, bucket, key string, expiry time.Duration) (string, error) {
	u, err := c.presign.PresignedGetObject(ctx, bucket, key, expiry, url.Values{})
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func caPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates parsed from %s", path)
	}
	return pool, nil
}

// List returns objects under prefix, skipping "directory" placeholder keys.
func (c *Client) List(ctx context.Context, bucket, prefix string) ([]Object, error) {
	ctx, cancel := c.listCtx(ctx)
	defer cancel()
	var out []Object
	for info := range c.mc.ListObjects(ctx, bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if info.Err != nil {
			return nil, info.Err
		}
		if strings.HasSuffix(info.Key, "/") {
			continue
		}
		out = append(out, Object{Key: info.Key, Size: info.Size, LastModified: info.LastModified})
	}
	return out, nil
}

// Get fetches an object's full contents.
func (c *Client) Get(ctx context.Context, bucket, key string) ([]byte, error) {
	ctx, g, cancel := c.guard(ctx)
	defer cancel()
	defer g.stop()

	obj, err := c.mc.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, stalledOr(g, err)
	}
	defer obj.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(&stallReader{r: obj, g: g}); err != nil {
		return nil, stalledOr(g, err)
	}
	return buf.Bytes(), nil
}

// GetLimited fetches an object but reads at most max bytes into memory. If the
// object is larger than max it returns ErrTooLarge without buffering the whole
// thing — the backstop that keeps a huge object from OOM-killing the pod even if
// its listed size was unknown or wrong.
func (c *Client) GetLimited(ctx context.Context, bucket, key string, max int64) ([]byte, error) {
	ctx, g, cancel := c.guard(ctx)
	defer cancel()
	defer g.stop()

	obj, err := c.mc.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, stalledOr(g, err)
	}
	defer obj.Close()
	var buf bytes.Buffer
	n, err := io.CopyN(&buf, &stallReader{r: obj, g: g}, max+1)
	if err != nil && err != io.EOF {
		return nil, stalledOr(g, err)
	}
	if n > max {
		return nil, ErrTooLarge
	}
	return buf.Bytes(), nil
}

// Stat reports whether key exists without transferring its contents. The API
// uses it to answer "is this object finished?" from durable storage rather than
// from the process's in-memory job history, which does not survive a restart.
func (c *Client) Stat(ctx context.Context, bucket, key string) (Object, bool, error) {
	ctx, cancel := c.opCtx(ctx)
	defer cancel()
	info, err := c.mc.StatObject(ctx, bucket, key, minio.StatObjectOptions{})
	if err != nil {
		resp := minio.ToErrorResponse(err)
		if resp.Code == "NoSuchKey" || resp.StatusCode == http.StatusNotFound {
			return Object{}, false, nil
		}
		return Object{}, false, err
	}
	return Object{Key: key, Size: info.Size, LastModified: info.LastModified}, true, nil
}

// Exists reports whether key exists and, if so, returns its contents.
func (c *Client) Exists(ctx context.Context, bucket, key string) (bool, []byte, error) {
	statCtx, cancel := c.opCtx(ctx)
	defer cancel()
	if _, err := c.mc.StatObject(statCtx, bucket, key, minio.StatObjectOptions{}); err != nil {
		resp := minio.ToErrorResponse(err)
		if resp.Code == "NoSuchKey" || resp.StatusCode == http.StatusNotFound {
			return false, nil, nil
		}
		return false, nil, err
	}
	data, err := c.Get(ctx, bucket, key)
	if err != nil {
		return false, nil, err
	}
	return true, data, nil
}

// Put uploads data to key.
func (c *Client) Put(ctx context.Context, bucket, key string, data []byte, contentType string) error {
	return c.PutStream(ctx, bucket, key, bytes.NewReader(data), int64(len(data)), contentType)
}

// PutStream uploads from a reader. minio-go's PutObject is reader-based already, so
// the byte-slice Put is the adapter here, not this.
//
// Guarded like the read path, and for the same reason: writing a scrubbed result
// back is as capable of hanging as fetching the input, and it hangs *after* the
// object has been scrubbed — so the work is done, uncommitted, and the queue is
// blocked behind it. The guard watches Reads rather than Writes here: the bytes
// are already in hand, so the observable signal is the client no longer draining
// them.
func (c *Client) PutStream(ctx context.Context, bucket, key string, r io.Reader, size int64, contentType string) error {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	ctx, g, cancel := c.guard(ctx)
	defer cancel()
	defer g.stop()

	_, err := c.mc.PutObject(ctx, bucket, key, &stallReader{r: r, g: g}, size,
		minio.PutObjectOptions{ContentType: contentType})
	if err != nil {
		return stalledOr(g, err)
	}
	return nil
}

// GetLimitedTo streams an object into w under a byte cap.
//
// Same contract as GetLimited — the cap is enforced while reading, so an oversized
// object is refused without ever being buffered whole — except the destination is
// the caller's writer, which lets the worker stage a large upload on scratch storage
// instead of the heap.
// A stall guard runs for the whole transfer. This is the read that wedged the
// single consumer indefinitely when a connection went quiet mid-body: it runs on
// the worker's long-lived context, so nothing else would ever have ended it.
func (c *Client) GetLimitedTo(ctx context.Context, w io.Writer, bucket, key string, max int64) (int64, error) {
	ctx, g, cancel := c.guard(ctx)
	defer cancel()
	defer g.stop()

	obj, err := c.mc.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return 0, stalledOr(g, err)
	}
	defer obj.Close()
	n, err := io.CopyN(&stallWriter{w: w, g: g}, obj, max+1)
	if err != nil && err != io.EOF {
		return n, stalledOr(g, err)
	}
	if n > max {
		return n, ErrTooLarge
	}
	return n, nil
}

// Move copies srcKey to dstKey within a bucket then deletes the source.
func (c *Client) Move(ctx context.Context, bucket, srcKey, dstKey string) error {
	ctx, cancel := c.opCtx(ctx)
	defer cancel()
	src := minio.CopySrcOptions{Bucket: bucket, Object: srcKey}
	dst := minio.CopyDestOptions{Bucket: bucket, Object: dstKey}
	if _, err := c.mc.CopyObject(ctx, dst, src); err != nil {
		return err
	}
	return c.mc.RemoveObject(ctx, bucket, srcKey, minio.RemoveObjectOptions{})
}

// Delete removes key.
func (c *Client) Delete(ctx context.Context, bucket, key string) error {
	ctx, cancel := c.opCtx(ctx)
	defer cancel()
	return c.mc.RemoveObject(ctx, bucket, key, minio.RemoveObjectOptions{})
}

// Healthy reports whether the MinIO endpoint is reachable and the bucket exists.
//
// The caller already gives this its own short deadline for the readiness probe;
// the bound here is a backstop for any other caller, so that "is the backend up?"
// can never itself be the thing that hangs.
func (c *Client) Healthy(ctx context.Context, bucket string) bool {
	ctx, cancel := c.opCtx(ctx)
	defer cancel()
	ok, err := c.mc.BucketExists(ctx, bucket)
	return err == nil && ok
}

// EnsureBucket creates the bucket if it does not exist (used by tooling/tests).
func (c *Client) EnsureBucket(ctx context.Context, bucket string) error {
	ctx, cancel := c.opCtx(ctx)
	defer cancel()
	ok, err := c.mc.BucketExists(ctx, bucket)
	if err != nil {
		return err
	}
	if !ok {
		return c.mc.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	}
	return nil
}
