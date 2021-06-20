package file

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Config struct {
	Path string `yaml:"path"`
}

type File struct {
	cfg *Config
}

func (_ *File) Name() string {
	return "file"
}

func (f *File) Upload(ctx context.Context, name string, r io.Reader) error {
	path := filepath.Join(f.cfg.Path, name)

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	if _, err := io.Copy(file, r); err != nil {
		return err
	}

	return file.Close()
}

func (f *File) Exists(ctx context.Context, name string) (bool, error) {
	info, err := os.Stat(filepath.Join(f.cfg.Path, name))
	if err != nil {
		if f.IsObjNotFoundErr(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat %s: %w", filepath.Join(f.cfg.Path, name), err)
	}
	return !info.IsDir(), nil
}

func (f *File) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	return f.GetRange(ctx, name, 0, -1)
}

type rangeReaderCloser struct {
	io.Reader
	f *os.File
}

func (r *rangeReaderCloser) Close() error {
	return r.f.Close()
}

// GetRange returns a new range reader for the given object name and range.
func (f *File) GetRange(_ context.Context, name string, off, length int64) (io.ReadCloser, error) {
	if name == "" {
		return nil, errors.New("object name is empty")
	}

	file := filepath.Join(f.cfg.Path, name)
	if _, err := os.Stat(file); err != nil {
		return nil, fmt.Errorf("error during stat %s: %w", file, err)
	}

	fd, err := os.OpenFile(filepath.Clean(file), os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}

	if off > 0 {
		_, err := fd.Seek(off, 0)
		if err != nil {
			return nil, fmt.Errorf("error during seek %v: %w", off, err)
		}
	}

	if length == -1 {
		return fd, nil
	}

	return &rangeReaderCloser{Reader: io.LimitReader(fd, length), f: fd}, nil
}

func (file *File) IsObjNotFoundErr(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}

func New(cfg *Config) *File {
	return &File{
		cfg: cfg,
	}
}
