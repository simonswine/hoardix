package cache

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/numtide/go-nix/hash"
	"github.com/numtide/go-nix/nar/narinfo"
	"github.com/numtide/go-nix/nixbase32"
	"github.com/numtide/go-nix/nixpath"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"gopkg.in/yaml.v3"

	"github.com/simonswine/hoardix/pkg/compression"
	"github.com/simonswine/hoardix/pkg/httputil"
	"github.com/simonswine/hoardix/pkg/storage"
	"github.com/simonswine/hoardix/pkg/token"
)

const metricNamespace = "hoardix"

var (
	metricNarinfoCacheHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "narinfo_metadata_cache_hits",
			Help:      "How many narinfo request have hit the metadata cache",
		},
		[]string{"cache_name", "substitutor"},
	)
	metricNarinfoCacheMisses = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "narinfo_metadata_cache_misses",
			Help:      "How many narinfo request have missed the metadata cache",
		},
		[]string{"cache_name"},
	)

	metricNarUploadBytes = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricNamespace,
			Name:      "nar_upload_size_bytes",
			Help:      "How big was a nar upload in bytes",
			Buckets:   prometheus.ExponentialBuckets(1024, 2, 10),
		},
		[]string{"cache_name"},
	)
)

type Config struct {
	Priority     *int8               `yaml:"priority,omitempty"`
	Public       *bool               `yaml:"public,omitempty"`
	PrivateKey   PrivateKey          `yaml:"private_key,omitempty"`
	Substituters []ConfigSubstituter `yaml:"substituters,omitempty"`
}

func unmarshalYAMLCacheKey(value *yaml.Node) (identifier string, key []byte, err error) {
	var stringValue string
	if err := value.Decode(&stringValue); err != nil {
		return "", nil, err
	}

	// find identifier
	posSplit := strings.LastIndex(stringValue, ":")
	if posSplit == -1 {
		return "", nil, fmt.Errorf("invalid format of key, expected '<identifier>:<key>'")
	}
	identifier = stringValue[0:posSplit]

	// parse base64 part
	keyBytes, err := base64.StdEncoding.DecodeString(stringValue[posSplit+1:])
	if err != nil {
		return "", nil, err
	}

	return identifier, keyBytes, nil
}

type PublicKey struct {
	ed25519.PublicKey
	Identifier string
}

func (c PublicKey) MarshalYAML() (interface{}, error) {
	return c.String(), nil
}

func (c PublicKey) String() string {
	return fmt.Sprintf("%s:%s", c.Identifier, base64.StdEncoding.EncodeToString(c.PublicKey))
}

func (c *PublicKey) UnmarshalYAML(value *yaml.Node) error {
	identifier, key, err := unmarshalYAMLCacheKey(value)
	if err != nil {
		return err
	}

	if exp, act := ed25519.PublicKeySize, len(key); exp != act {
		return fmt.Errorf("invalid public key length %d (expected %d bytes)", act, exp)
	}

	c.PublicKey = ed25519.PublicKey(key)
	c.Identifier = identifier
	return nil
}

type PrivateKey struct {
	ed25519.PrivateKey
	Identifier string
}

func (c PrivateKey) MarshalYAML() (interface{}, error) {
	return fmt.Sprintf("%s:<redacted>", c.Identifier), nil
}

func (c *PrivateKey) UnmarshalYAML(value *yaml.Node) error {
	identifier, key, err := unmarshalYAMLCacheKey(value)
	if err != nil {
		return err
	}

	if exp, act := ed25519.PrivateKeySize, len(key); exp != act {
		return fmt.Errorf("invalid private key length %d (expected %d bytes)", act, exp)
	}

	c.PrivateKey = ed25519.PrivateKey(key)
	c.Identifier = identifier
	return nil
}

func (c *PrivateKey) PublicKey() PublicKey {
	publicKey := make([]byte, ed25519.PublicKeySize)
	copy(publicKey, c.PrivateKey[32:])

	return PublicKey{
		Identifier: c.Identifier,
		PublicKey:  ed25519.PublicKey(publicKey),
	}
}

type Cache struct {
	logger zerolog.Logger
	name   string
	cfg    *Config

	storage      storage.Storage
	substituters *substituters
	narinfoCache NarinfoCache
	url          string
}

type NarinfoCache interface {
	Set(key string, entry []byte) error
	Get(key string) ([]byte, error)
}

type App interface {
	BaseURL() *url.URL
	NarinfoCache() NarinfoCache
	Logger() zerolog.Logger
	Storage() storage.Storage
}

func New(name string, cfg *Config, app App) (*Cache, error) {
	url := app.BaseURL()
	url.Host = name + "." + url.Host

	c := &Cache{
		name:         name,
		cfg:          cfg,
		logger:       app.Logger().With().Str("cache", name).Logger(),
		storage:      storage.WithPrefix(app.Storage(), filepath.Join("cache", name)),
		narinfoCache: app.NarinfoCache(),
		url:          url.String(),
	}

	var err error
	c.substituters, err = newSubstituters(cfg.Substituters, c)

	if err != nil {
		return nil, err
	}

	return c, nil
}

type cacheInfo struct {
	Name              string   `json:"name"`
	URI               string   `json:"uri"`
	IsPublic          bool     `json:"isPublic"`
	PublicSigningKeys []string `json:"publicSigningKeys"`
	Permission        string   `json:"permission"`
	GithubUsername    string   `json:"githubUsername"`
}

func capitalizeString(s string) string {
	for index, value := range s {
		return string(unicode.ToUpper(value)) + s[index+1:]
	}
	return ""
}

func (c *Cache) HandleCacheInfo(w http.ResponseWriter, r *http.Request) {
	if !c.verifyAuthorized(token.PermissionRead, w, r) {
		return
	}

	perm := token.PermissionFromContext(r.Context())
	if perm == token.PermissionAnonymous {
		perm = token.PermissionRead
	}

	w.Header().Set("Content-Type", "application/json")

	info := cacheInfo{
		Name:       c.name,
		URI:        c.url,
		IsPublic:   false,
		Permission: capitalizeString(perm.String()),
		PublicSigningKeys: []string{
			c.cfg.PrivateKey.PublicKey().String(),
		},
	}
	if err := json.NewEncoder(w).Encode(&info); err != nil {
		httputil.WriteError(w, r, &httputil.Error{
			Err: err,
		})
		return
	}

}

func (c *Cache) narinfoURL(hash string) string {
	if hash == "" {
		return c.url
	}
	return filepath.Join(c.url, fmt.Sprintf("%s.narinfo", hash))
}

func (c *Cache) lookupNarinfo(ctx context.Context, hash string) (*narInfo, error) {
	resp, err := c.storage.Get(ctx, fmt.Sprintf("%s.narinfo", hash))
	if c.storage.IsObjNotFoundErr(err) {
		return nil, errNarinfoNotFound
	} else if err != nil {
		return nil, err
	}
	defer resp.Close()

	narInfo, err := validateNarSignature(resp, []PublicKey{c.cfg.PrivateKey.PublicKey()})
	if err != nil {
		return nil, err
	}

	return narInfo, nil
}

func (c *Cache) Priority() int8 {
	if c.cfg.Priority == nil {
		return 41
	}
	return *c.cfg.Priority
}

func (c *Cache) HandleCacheRead(w http.ResponseWriter, r *http.Request) {
	// verify authorization
	if !c.verifyAuthorized(token.PermissionRead, w, r) {
		return
	}

	// return cache info
	if r.URL.Path == "/nix-cache-info" {
		_, _ = w.Write([]byte(fmt.Sprintf(strings.Join([]string{
			"StoreDir: %s",
			"WantMassQuery: 1",
			"Priority: %d",
			"",
		}, "\n"), nixpath.StoreDir, c.Priority())))
		return
	}

	// check storage for content
	body, err := c.storage.Get(r.Context(), r.URL.Path)
	if c.storage.IsObjNotFoundErr(err) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		httputil.WriteError(w, r, &httputil.Error{
			Err: err,
		})
		return
	}

	defer body.Close()
	if _, err := io.Copy(w, body); err != nil {
		httputil.WriteError(w, r, &httputil.Error{
			Err: err,
		})
		return
	}
}

func (c *Cache) HandleCacheNarinfo(w http.ResponseWriter, r *http.Request) {
	if !c.verifyAuthorized(token.PermissionWrite, w, r) {
		return

	}
	var inputHashes []string
	if err := json.NewDecoder(r.Body).Decode(&inputHashes); err != nil {
		httputil.WriteError(w, r, &httputil.Error{
			Err: err,
		})
		return
	}

	outputHashes, err := c.substituters.lookupHashes(r.Context(), inputHashes)
	if err != nil {
		httputil.WriteError(w, r, &httputil.Error{
			Err: err,
		})
		return
	}
	total := len(inputHashes)
	missing := len(outputHashes)
	hlog.FromRequest(r).Debug().Int("total", total).Int("found", total-missing).Int("missing", missing).Msg("cache narinfo")

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(&outputHashes); err != nil {
		httputil.WriteError(w, r, &httputil.Error{
			Err: err,
		})
		return
	}
}

func (c *Cache) HandleUploadNar(w http.ResponseWriter, r *http.Request) {
	if !c.verifyAuthorized(token.PermissionWrite, w, r) {
		return
	}

	bodyHash := sha256.New()
	data, err := ioutil.ReadAll(io.TeeReader(r.Body, bodyHash))
	if err != nil {
		httputil.WriteError(w, r, &httputil.Error{Err: fmt.Errorf("error reading request body: %w", err)})
		return
	}

	// check if file has valid XZ headers
	if err := compression.IsXZ(data); err != nil {
		httputil.WriteError(w, r, &httputil.Error{Err: err, Msg: err.Error(), StatusCode: http.StatusBadRequest})
		return
	}

	narHash := &hash.Hash{
		Digest:   bodyHash.Sum(nil),
		HashType: hash.HashTypeSha256,
	}

	path := narPath(narHash, compression.TypeXZ)
	if err := c.storage.Upload(
		r.Context(),
		path,
		bytes.NewReader(data),
	); err != nil {
		httputil.WriteError(w, r, &httputil.Error{Err: err})
		return
	}

	metricNarUploadBytes.WithLabelValues(c.name).Observe(float64(len(data)))

	c.logger.Info().Str("path", path).Int("size", len(data)).Msg("successfully uploaded nar")

	w.WriteHeader(http.StatusOK)
}

func (c *Cache) verifyAuthorized(minimumPermission token.Permission, w http.ResponseWriter, r *http.Request) bool {
	existingPermission := token.PermissionFromContext(r.Context())
	if minimumPermission == token.PermissionRead && c.cfg.Public != nil && *c.cfg.Public {
		return true
	}
	if existingPermission >= minimumPermission {
		return true
	}

	httputil.WriteError(w, r, &httputil.Error{
		StatusCode: http.StatusUnauthorized,
		Msg:        "not authorized",
	})
	return false
}

func (c *Cache) HandleUploadNarinfo(w http.ResponseWriter, r *http.Request) {
	if !c.verifyAuthorized(token.PermissionWrite, w, r) {
		return
	}

	var inputNarinfo = struct {
		CStoreHash   string   `json:"cStoreHash"`
		CStoreSuffix string   `json:"cStoreSuffix"`
		CNarHash     nixHash  `json:"cNarHash"`
		CNarSize     int      `json:"cNarSize"`
		CFileHash    nixHash  `json:"cFileHash"`
		CFileSize    int      `json:"cFileSize"`
		CReferences  []string `json:"cReferences"`
		CDeriver     string   `json:"cDeriver"`
		CSig         string   `json:"cSig"`
	}{}

	d, _ := ioutil.ReadAll(r.Body)

	if err := json.NewDecoder(bytes.NewReader(d)).Decode(&inputNarinfo); err != nil {
		httputil.WriteError(w, r, &httputil.Error{
			StatusCode: http.StatusInternalServerError,
			Err:        err,
			Msg:        err.Error(),
		})
		return
	}

	outputNarinfo := &narinfo.NarInfo{
		StorePath:   filepath.Join(nixpath.StoreDir, inputNarinfo.CStoreHash+"-"+inputNarinfo.CStoreSuffix),
		URL:         narPath(inputNarinfo.CFileHash.hash, compression.TypeXZ),
		Compression: "xz", // TODO: Figure out how well that works as a hardcoded value
		FileHash:    inputNarinfo.CFileHash.hash,
		FileSize:    inputNarinfo.CFileSize,
		NarHash:     inputNarinfo.CNarHash.hash,
		NarSize:     inputNarinfo.CNarSize,
		References:  inputNarinfo.CReferences,
		Deriver:     inputNarinfo.CDeriver,
	}

	// TODO: check for URL

	// sign narinfo
	ni := &narInfo{outputNarinfo}
	outputNarinfo.Signatures = append(outputNarinfo.Signatures, &narinfo.Signature{
		KeyName: c.cfg.PrivateKey.Identifier,
		Digest:  ed25519.Sign(c.cfg.PrivateKey.PrivateKey, ni.message()),
	})

	err := c.storage.Upload(r.Context(), fmt.Sprintf("%s.narinfo", inputNarinfo.CStoreHash), strings.NewReader(outputNarinfo.String()))
	if err != nil {
		httputil.WriteError(w, r, &httputil.Error{
			StatusCode: http.StatusInternalServerError,
			Err:        err,
			Msg:        "error uploading narinfo",
		})
		return
	}

	c.logger.Info().Str("path", outputNarinfo.StorePath).Str("nar_path", outputNarinfo.URL).Msg("successfully uploaded narinfo")

	w.WriteHeader(http.StatusOK)
}

func narPath(h *hash.Hash, cmp compression.Type) string {
	if cmp != compression.TypeXZ {
		panic("unsupported compression")
	}
	return fmt.Sprintf("nar/%s.nar.xz", nixbase32.EncodeToString(h.Digest))
}

type nixHash struct {
	hash *hash.Hash
}

func (n *nixHash) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		n.hash = nil
		return nil
	}

	var str string

	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}

	// check if hash a prefix
	if strings.HasPrefix(str, hash.HashTypeSha256) || strings.HasPrefix(str, hash.HashTypeSha512) {
		h, err := hash.ParseNixBase32(str)
		if err != nil {
			return fmt.Errorf("error parsing hash '%s': %w", str, err)
		}
		n.hash = h
	} else if len(str) == 256/4 {
		digest, err := hex.DecodeString(str)
		if err != nil {
			return err
		}
		n.hash = &hash.Hash{
			Digest:   digest,
			HashType: hash.HashTypeSha256,
		}
	} else if len(str) == 512/4 {
		digest, err := hex.DecodeString(str)
		if err != nil {
			return err
		}
		n.hash = &hash.Hash{
			Digest:   digest,
			HashType: hash.HashTypeSha512,
		}
	} else {
		return fmt.Errorf("error unknown hash format in '%s'", str)
	}

	return nil
}
