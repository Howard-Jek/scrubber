// Package store wraps the MinIO/S3 object operations the worker needs: list new
// input objects, fetch bytes, put results, and mark an input processed (move or
// delete). It is deliberately small and mockable via the ObjectStore interface.
package store

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Object is a listed object's identity.
type Object struct {
	Key  string
	Size int64
}

// ObjectStore is the subset of behavior the worker depends on (mockable in tests).
type ObjectStore interface {
	List(ctx context.Context, bucket, prefix string) ([]Object, error)
	Get(ctx context.Context, bucket, key string) ([]byte, error)
	Exists(ctx context.Context, bucket, key string) (bool, []byte, error)
	Put(ctx context.Context, bucket, key string, data []byte, contentType string) error
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
}

// Client is the concrete MinIO-backed ObjectStore.
type Client struct {
	mc *minio.Client
}

// New builds a MinIO client from Config.
func New(cfg Config) (*Client, error) {
	opts := &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseTLS,
		Region: cfg.Region,
	}
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
	return &Client{mc: mc}, nil
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
	var out []Object
	for info := range c.mc.ListObjects(ctx, bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if info.Err != nil {
			return nil, info.Err
		}
		if strings.HasSuffix(info.Key, "/") {
			continue
		}
		out = append(out, Object{Key: info.Key, Size: info.Size})
	}
	return out, nil
}

// Get fetches an object's full contents.
func (c *Client) Get(ctx context.Context, bucket, key string) ([]byte, error) {
	obj, err := c.mc.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer obj.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(obj); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Exists reports whether key exists and, if so, returns its contents.
func (c *Client) Exists(ctx context.Context, bucket, key string) (bool, []byte, error) {
	if _, err := c.mc.StatObject(ctx, bucket, key, minio.StatObjectOptions{}); err != nil {
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
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	_, err := c.mc.PutObject(ctx, bucket, key, bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: contentType})
	return err
}

// Move copies srcKey to dstKey within a bucket then deletes the source.
func (c *Client) Move(ctx context.Context, bucket, srcKey, dstKey string) error {
	src := minio.CopySrcOptions{Bucket: bucket, Object: srcKey}
	dst := minio.CopyDestOptions{Bucket: bucket, Object: dstKey}
	if _, err := c.mc.CopyObject(ctx, dst, src); err != nil {
		return err
	}
	return c.mc.RemoveObject(ctx, bucket, srcKey, minio.RemoveObjectOptions{})
}

// Delete removes key.
func (c *Client) Delete(ctx context.Context, bucket, key string) error {
	return c.mc.RemoveObject(ctx, bucket, key, minio.RemoveObjectOptions{})
}

// Healthy reports whether the MinIO endpoint is reachable and the bucket exists.
func (c *Client) Healthy(ctx context.Context, bucket string) bool {
	ok, err := c.mc.BucketExists(ctx, bucket)
	return err == nil && ok
}

// EnsureBucket creates the bucket if it does not exist (used by tooling/tests).
func (c *Client) EnsureBucket(ctx context.Context, bucket string) error {
	ok, err := c.mc.BucketExists(ctx, bucket)
	if err != nil {
		return err
	}
	if !ok {
		return c.mc.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	}
	return nil
}
