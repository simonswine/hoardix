package hoardix

import (
	"bufio"
	"bytes"
	"fmt"

	"net/http"
	"os"
	"strings"
	"time"

	"github.com/allegro/bigcache/v3"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"

	"github.com/simonswine/hoardix/pkg/cache"
	"github.com/simonswine/hoardix/pkg/httputil"
	"github.com/simonswine/hoardix/pkg/storage"
	"github.com/simonswine/hoardix/pkg/token"
	"github.com/simonswine/hoardix/pkg/validate"
)

type Config struct {
	BaseDomain string                  `yaml:"base_domain,omitempty"`
	Tokens     []token.Config          `yaml:"tokens,omitempty"`
	Storage    storage.Config          `yaml:"storage,omitempty"`
	Caches     map[string]cache.Config `yaml:"caches,omitempty"`
}

func (c *Config) String() string {
	var buf = new(bytes.Buffer)

	enc := yaml.NewEncoder(buf)
	enc.SetIndent(2)
	if err := enc.Encode(c); err != nil {
		panic(err)
	}

	return buf.String()
}

func readConfigFromFile(path string) (*Config, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("error opening YAML file: %w", err)
	}

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)

	var config Config
	if err := dec.Decode(&config); err != nil {
		return nil, fmt.Errorf("error parsing YAML file: %w", err)
	}

	return &config, nil
}

type App struct {
	cfg *Config

	storage storage.Storage
	logger  zerolog.Logger

	caches map[string]*cache.Cache

	narinfoCache *bigcache.BigCache
}

func New() *App {
	logger :=
		log.Output(zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: time.RFC3339Nano,
		})

	return &App{
		logger: logger,
		caches: make(map[string]*cache.Cache),
	}
}

//api/v1/cache/packer-kubernetes-hcloud
//api/v1/cache/packer-kubernetes-hcloud/narinfo

func (a *App) handleCacheInfo(w http.ResponseWriter, r *http.Request) {
	cache := a.cacheOrNotFound(w, r)
	if cache == nil {
		return
	}
	cache.HandleCacheInfo(w, r)
}

func (a *App) handleUploadNar(w http.ResponseWriter, r *http.Request) {
	cache := a.cacheOrNotFound(w, r)
	if cache == nil {
		return
	}
	cache.HandleUploadNar(w, r)
}

func (a *App) handleUploadNarinfo(w http.ResponseWriter, r *http.Request) {
	cache := a.cacheOrNotFound(w, r)
	if cache == nil {
		return
	}
	cache.HandleUploadNarinfo(w, r)
}

// relative path in bucket

func (a *App) cacheOrNotFound(w http.ResponseWriter, r *http.Request) *cache.Cache {
	vars := mux.Vars(r)
	cacheName := vars["cache_name"]

	c, ok := a.caches[cacheName]
	if ok {
		return c
	}

	httputil.WriteError(w, r, &httputil.Error{
		StatusCode: http.StatusNotFound,
		Msg:        fmt.Sprintf("cache '%s' not found", cacheName),
		//err: "cache not found",
	})

	return nil
}

func (a *App) handleCacheNarinfo(w http.ResponseWriter, r *http.Request) {
	cache := a.cacheOrNotFound(w, r)
	if cache == nil {
		return
	}
	cache.HandleCacheNarinfo(w, r)
}

func (a *App) handleCacheRead(w http.ResponseWriter, r *http.Request) {
	cache := a.cacheOrNotFound(w, r)
	if cache == nil {
		return
	}
	cache.HandleCacheRead(w, r)
}

func (a *App) initRouter() http.Handler {
	router := mux.NewRouter().StrictSlash(true)

	router.Use(token.New(a.cfg.Tokens).Middleware)

	router.Host(fmt.Sprintf("{cache_name:[a-z0-9-_]+}.%s", a.cfg.BaseDomain)).HandlerFunc(a.handleCacheRead)

	apiRouter := router.PathPrefix("/api/v1").Subrouter()
	apiRouter.HandleFunc("/cache", a.handleCacheInfo).Methods("GET")
	apiRouter.HandleFunc("/cache/{cache_name:[a-z0-9-_]+}", a.handleCacheInfo).Methods("GET")
	apiRouter.HandleFunc("/cache/{cache_name:[a-z0-9-_]+}/narinfo", a.handleCacheNarinfo).Methods("POST")
	apiRouter.HandleFunc("/cache/{cache_name:[a-z0-9-_]+}/nar", a.handleUploadNar).Methods("POST")
	apiRouter.HandleFunc("/cache/{cache_name:[a-z0-9-_]+}/{path_narinfo:[a-z0-9-_]+}.narinfo", a.handleUploadNarinfo).Methods("POST")

	return router
}

func (a *App) Run() error {
	var err error
	a.cfg, err = readConfigFromFile("config.yaml")
	if err != nil {
		return err
	}

	a.logger.Debug().Msg("parsed config")
	scanner := bufio.NewScanner(strings.NewReader(a.cfg.String()))
	for scanner.Scan() {
		a.logger.Debug().Msg(scanner.Text())
	}

	// init storage
	a.storage, err = storage.New(&a.cfg.Storage)
	if err != nil {
		return err
	}

	// create narinfo cache
	bigcacheCfg := bigcache.DefaultConfig(time.Hour * 24)
	bigcacheCfg.HardMaxCacheSize = 512
	a.narinfoCache, err = bigcache.NewBigCache(bigcacheCfg)
	if err != nil {
		return err
	}

	// initialize caches
	for name, cfg := range a.cfg.Caches {
		if errs := validate.IsValidName(name); len(errs) != 0 {
			return fmt.Errorf("invalid cache name %s: %s", name, strings.Join(errs, ","))
		}

		a.caches[name], err = cache.New(
			name,
			&cfg,
			a,
		)
		if err != nil {
			return err
		}
	}

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

	if err := http.ListenAndServe(":5000", logHandler(accessHandler(a.initRouter()))); err != nil {
		a.logger.Fatal().Err(err).Msg("error listening to HTTP")
	}

	return nil
}

func (a *App) Logger() zerolog.Logger {
	return a.logger
}

func (a *App) NarinfoCache() cache.NarinfoCache {
	return a.narinfoCache
}

func (a *App) Storage() storage.Storage {
	return a.storage
}

func (a *App) BaseDomain() string {
	return a.cfg.BaseDomain
}
