package cache

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/numtide/go-nix/libstore"
	"github.com/numtide/go-nix/nar/narinfo"
	"github.com/numtide/go-nix/nixpath"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

var errNarinfoNotFound = errors.New("narinfo not in cache")

type ConfigSubstituter struct {
	URL       string    `yaml:"url,omitempty"`
	PublicKey PublicKey `yaml:"public_key,omitempty"`
}

type libstoreSubstituter struct {
	url       string
	reader    libstore.BinaryCacheReader
	publicKey PublicKey
}

type narInfo struct {
	*narinfo.NarInfo
}

func (ni *narInfo) message() []byte {
	var referencesStorePaths = make([]string, len(ni.References))
	for pos := range referencesStorePaths {
		referencesStorePaths[pos] = filepath.Join(nixpath.StoreDir, ni.References[pos])
	}

	// build content message
	return []byte(fmt.Sprintf(
		"1;%s;%s;%d;%s",
		ni.StorePath,
		ni.NarHash,
		ni.NarSize,
		strings.Join(referencesStorePaths, ","),
	))
}

func (ni *narInfo) validateSignature(keys []PublicKey) error {
	message := ni.message()

	// validate signature
	for _, key := range keys {
		for _, signature := range ni.Signatures {
			if signature.KeyName == key.Identifier {
				if !ed25519.Verify(key.PublicKey, message, signature.Digest) {
					return fmt.Errorf("signature validation failed for key %s", key.Identifier)
				} else {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("no matching signature found")
}

func validateNarSignature(r io.Reader, keys []PublicKey) (*narInfo, error) {
	innerNI, err := narinfo.Parse(r)
	if err != nil {
		return nil, err
	}
	ni := &narInfo{
		NarInfo: innerNI,
	}

	if err := ni.validateSignature(keys); err != nil {
		return nil, err
	}
	return ni, nil
}

func (l *libstoreSubstituter) lookupNarinfo(ctx context.Context, hash string) (*narInfo, error) {
	resp, err := l.reader.GetFile(ctx, fmt.Sprintf("%s.narinfo", hash))
	if err != nil {
		if err.Error() == "unexpected file status '404 Not Found'" {
			return nil, errNarinfoNotFound
		}
		return nil, err
	}
	defer resp.Close()

	narInfo, err := validateNarSignature(resp, []PublicKey{l.publicKey})
	if err != nil {
		return nil, err
	}

	return narInfo, nil
}

func (l *libstoreSubstituter) narinfoURL(hash string) string {
	return filepath.Join(l.url, fmt.Sprintf("%s.narinfo", hash))
}

type substituter interface {
	// lookup narinfo, parse it and validate signature against the public key
	lookupNarinfo(ctx context.Context, hash string) (*narInfo, error)
	// get a fixed url per cache
	narinfoURL(string) string
}

type substituters struct {
	substituters []substituter
	narinfoCache NarinfoCache
}

func newSubstituters(cfgs []ConfigSubstituter, cache *Cache) (*substituters, error) {

	ctx := context.Background()

	s := &substituters{
		substituters: make([]substituter, len(cfgs)+1),
		narinfoCache: cache.narinfoCache,
	}
	s.substituters[0] = cache

	for pos, cfg := range cfgs {
		cacheReader, err := libstore.NewBinaryCacheReader(ctx, cfg.URL)
		if err != nil {
			return nil, err
		}
		s.substituters[pos+1] = &libstoreSubstituter{
			reader:    cacheReader,
			url:       cfg.URL,
			publicKey: cfg.PublicKey,
		}
	}

	return s, nil
}

func (s *substituters) setCacheNarinfo(ctx context.Context, url string, ni *narInfo) error {
	var buf bytes.Buffer

	if err := gob.NewEncoder(&buf).Encode(ni); err != nil {
		return err
	}

	return s.narinfoCache.Set(url, buf.Bytes())
}

func (s *substituters) cachedLookupHash(ctx context.Context, hash string) (bool, error) {
	for _, subst := range s.substituters {
		url := subst.narinfoURL(hash)

		// check cache for hit
		_, err := s.narinfoCache.Get(url)
		if err == nil {
			return true, nil
		}
	}

	return s.lookupHash(ctx, hash)
}

func (s *substituters) lookupHash(ctx context.Context, hash string) (bool, error) {
	for _, subst := range s.substituters {
		if ni, err := subst.lookupNarinfo(ctx, hash); err != nil && err != errNarinfoNotFound {
			return false, err
		} else if err == nil {
			// save cache
			if err := s.setCacheNarinfo(ctx, subst.narinfoURL(hash), ni); err != nil {
				return false, fmt.Errorf("failed to set narinfo cache: %w", err)
			}
			return true, nil
		}
	}

	return false, nil
}

func (s *substituters) lookupHashes(ctx context.Context, hashes []string) ([]string, error) {
	var workerNum int64 = 16

	foundCh := make(chan string)
	foundMap := make(map[string]struct{})
	done := make(chan struct{})

	// gather results
	go func() {
		defer close(done)
		for found := range foundCh {
			foundMap[found] = struct{}{}
		}
	}()

	group, ctx := errgroup.WithContext(context.Background())

	group.Go(func() error {
		sem := semaphore.NewWeighted(workerNum)

		for pos := range hashes {
			if err := sem.Acquire(ctx, 1); err != nil {
				return err
			}

			hash := hashes[pos]

			group.Go(func() error {
				defer sem.Release(1)

				if found, err := s.cachedLookupHash(ctx, hash); err != nil {
					return err
				} else if found {
					foundCh <- hash
				}
				return nil
			})
		}

		return nil
	})

	if err := group.Wait(); err != nil {
		return nil, err
	}

	close(foundCh)
	<-done

	var out = make([]string, 0, len(hashes)-len(foundMap))
	for _, hash := range hashes {
		if _, ok := foundMap[hash]; !ok {
			out = append(out, hash)
		}
	}
	return out, nil
}
