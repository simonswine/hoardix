package cachix

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/numtide/go-nix/libstore"
	"github.com/numtide/go-nix/nar/narinfo"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Storage ConfigStorage `yaml:"storage"`
	Caches  map[string]ConfigCache
}

type ConfigStorage struct {
	S3 *ConfigStorage `yaml:"s3"`
}

type ConfigStorageS3 struct {
	Region    string `yaml:"region"`
	Bucket    string `yaml:"bucket"`
	Endpoint  string `yaml:"endpoint"`
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
}

type ConfigCache struct {
	Name         string
	PublicKey    CachePublicKey      `yaml:"public_key"`
	Substituters []ConfigSubstituter `yaml:"substituters"`
}

type ConfigSubstituter struct {
	URL       string         `yaml:"url"`
	PublicKey CachePublicKey `yaml:"public_key"`
}

type CachePublicKey string

func readConfigFromFile(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading YAML file: %w", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("error parsing YAML file: %w", err)
	}

	return &config, nil
}

type App struct {
	cfg *Config

	logger zerolog.Logger
}

func New() *App {
	logger := zerolog.New(os.Stderr).With().
		Timestamp().
		Logger()

	return &App{
		logger: logger,
	}
}

//api/v1/cache/packer-kubernetes-hcloud
//api/v1/cache/packer-kubernetes-hcloud/narinfo

type CacheInfo struct {
	Name              string   `json:"name"`
	URI               string   `json:"uri"`
	IsPublic          bool     `json:"is_public"`
	PublicSigningKeys []string `json:"public_signing_keys"`
	Permission        string   `json:"permission"`
}

func (a *App) handleCacheInfo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	cacheName := vars["cache_name"]

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&CacheInfo{Name: cacheName, IsPublic: true, Permission: "Read"})
}

func (a *App) validateNarSignature(r io.Reader) (*narinfo.NarInfo, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	ni, err := narinfo.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	var referencesStorePaths = make([]string, len(ni.References))
	for pos := range referencesStorePaths {
		referencesStorePaths[pos] = "/nix/store/" + ni.References[pos]
	}

	message := fmt.Sprintf(
		"1;%s;%s;%d;%s",
		ni.StorePath,
		ni.NarHash,
		ni.NarSize,
		strings.Join(referencesStorePaths, ","),
	)

	// build content hash
	h := sha256.New()
	posSig := bytes.Index(data, []byte("\nSig: "))
	if posSig != -1 {
		posSig += 1
	}
	a.logger.Debug().Bytes("data", data[0:posSig]).Msg("build hash")
	_, err = h.Write(data[0:posSig])
	if err != nil {
		return nil, fmt.Errorf("error generating sha256 hash: %w", err)
	}

	// validate signature
	publicKeyBytes, err := base64.StdEncoding.DecodeString("6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=")
	if err != nil {
		return nil, err
	}

	if !ed25519.Verify(ed25519.PublicKey(publicKeyBytes), []byte(message), ni.Signatures[0].Digest) {
		return nil, fmt.Errorf("signature validation failed")
	}

	return ni, nil
}

func (a *App) handleCacheNarinfo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	cacheName := vars["cache_name"]

	var inputHashes []string
	json.NewDecoder(r.Body).Decode(&inputHashes)

	// libstore
	upstream := libstore.DefaultCache()

	for _, h := range inputHashes[0:5] {
		resp, err := upstream.GetFile(r.Context(), fmt.Sprintf("%s.narinfo", h))
		if err != nil {
			a.logger.Warn().Str("hash", h).Err(err).Msg("error requstion upstream")
			continue
		}

		narInfo, err := a.validateNarSignature(resp)
		resp.Close()
		if err != nil {
			a.logger.Warn().Str("hash", h).Err(err).Msg("error parsing narinfo")
			continue
		}

		a.logger.Info().Str("hash", h).Str("data", narInfo.String()).Msg("found narinfo in substistutor")

	}

	hlog.FromRequest(r).Debug().Str("cache", cacheName).Strs("input_hashes", inputHashes).Msg("xxx")

	outputHashes := []string{}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&outputHashes)

}

func (a *App) Run() error {
	cfg, err := readConfigFromFile("config.yaml")
	if err != nil {
		return err
	}
	a.cfg = cfg

	a.logger.Debug().Msgf("parsed config %+#v", cfg)

	//apiRouter := mux.NewRouter().StrictSlash(true)
	router := mux.NewRouter().StrictSlash(true)

	apiRouter := router.PathPrefix("/api/v1").Subrouter()
	apiRouter.HandleFunc("/cache", a.handleCacheInfo).Methods("GET")
	apiRouter.HandleFunc("/cache/{cache_name:[a-z0-9-_]+}", a.handleCacheInfo).Methods("GET")
	apiRouter.HandleFunc("/cache/{cache_name:[a-z0-9-_]+}/narinfo", a.handleCacheNarinfo).Methods("POST")

	logHandler := hlog.NewHandler(a.logger)

	accessHandler := hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		hlog.FromRequest(r).Debug().
			Str("method", r.Method).
			Stringer("url", r.URL).
			Int("status", status).
			Int("size", size).
			Dur("duration", duration).
			Msg("")
	})

	log.Fatal(http.ListenAndServe(":5000", logHandler(accessHandler(router))))

	return nil
}
