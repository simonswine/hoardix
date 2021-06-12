package storage

import (
	"context"
	"fmt"
	"io"
	"path/filepath"

	"github.com/simonswine/hoardix/pkg/storage/file"
	"github.com/simonswine/hoardix/pkg/storage/s3"
)

type Config struct {
	S3   *s3.Config   `yaml:"s3,omitempty"`
	File *file.Config `yaml:"file,omitempty"`
}

type Storage interface {
	Name() string
	Upload(ctx context.Context, name string, r io.Reader) error
	Get(ctx context.Context, name string) (io.ReadCloser, error)
	Exists(ctx context.Context, name string) (bool, error)
	IsObjNotFoundErr(err error) bool
}

func New(cfg *Config) (Storage, error) {

	var storages []Storage

	if cfg.S3 != nil {
		storages = append(storages, s3.New(cfg.S3))
	}

	if cfg.File != nil {
		storages = append(storages, file.New(cfg.File))
	}

	if len(storages) == 1 {
		return storages[0], nil
	}
	if len(storages) > 1 {
		return nil, fmt.Errorf("more than one storage specified: %+v", storages)
	}

	return file.New(&file.Config{
		Path: "./data",
	}), nil
}

type withPrefix struct {
	wrapped Storage
	prefix  string
}

func (w *withPrefix) Name() string {
	return w.withPrefix(w.wrapped.Name())
}

func (w *withPrefix) withPrefix(name string) string {
	return filepath.Join(w.prefix, name)
}

func (w *withPrefix) Upload(ctx context.Context, name string, r io.Reader) error {
	return w.wrapped.Upload(ctx, w.withPrefix(name), r)
}

func (w *withPrefix) Exists(ctx context.Context, name string) (bool, error) {
	return w.wrapped.Exists(ctx, w.withPrefix(name))
}

func (w *withPrefix) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	return w.wrapped.Get(ctx, w.withPrefix(name))
}

func (w *withPrefix) IsObjNotFoundErr(err error) bool {
	return w.wrapped.IsObjNotFoundErr(err)
}

func WithPrefix(storage Storage, prefix string) Storage {
	return &withPrefix{
		wrapped: storage,
		prefix:  prefix,
	}
}
