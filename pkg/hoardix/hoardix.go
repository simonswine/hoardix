package hoardix

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/signal"
	"runtime"
	"strconv"

	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/allegro/bigcache/v3"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

var (
	version         string = "unknown"
	commitHash      string = "unknown"
	commitTimestamp string = "unknown"
)

type Config struct {
	BaseURL           URL                     `yaml:"base_url,omitempty"`
	ListenPort        *int                    `yaml:"listen_port,omitempty"`
	MetricsListenPort *int                    `yaml:"metrics_listen_port,omitempty"`
	Tokens            []token.Config          `yaml:"tokens,omitempty"`
	Storage           storage.Config          `yaml:"storage,omitempty"`
	Caches            map[string]cache.Config `yaml:"caches,omitempty"`
}

type URL struct {
	*url.URL
}

func (u URL) MarshalYAML() (interface{}, error) {
	return u.URL.String(), nil
}

func (u *URL) UnmarshalYAML(value *yaml.Node) error {
	var strValue string
	if err := value.Decode(&strValue); err != nil {
		return err
	}

	url, err := url.Parse(strValue)
	if err != nil {
		return err
	}
	u.URL = url
	return nil
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

	// check hostname for cache name
	hostMatcher := fmt.Sprintf("{cache_name:[a-z0-9-_]+}.%s", a.cfg.BaseURL.Hostname())

	router.Path(`/nix-cache-info`).Host(hostMatcher).Methods("GET").HandlerFunc(a.handleCacheRead)
	router.Path(`/{path_narinfo:[a-z0-9-_]+}.narinfo`).Host(hostMatcher).Methods("GET").HandlerFunc(a.handleCacheRead)
	router.Path(`/nar/{path_nar:[a-z0-9-_]+}.nar.xz`).Host(hostMatcher).Methods("GET").HandlerFunc(a.handleCacheRead)

	apiRouter := router.PathPrefix("/api/v1").Subrouter()
	apiRouter.HandleFunc("/cache", a.handleCacheInfo).Methods("GET")
	apiRouter.HandleFunc("/cache/{cache_name:[a-z0-9-_]+}", a.handleCacheInfo).Methods("GET")
	apiRouter.HandleFunc("/cache/{cache_name:[a-z0-9-_]+}/narinfo", a.handleCacheNarinfo).Methods("POST")
	apiRouter.HandleFunc("/cache/{cache_name:[a-z0-9-_]+}/nar", a.handleUploadNar).Methods("POST")
	apiRouter.HandleFunc("/cache/{cache_name:[a-z0-9-_]+}/{path_narinfo:[a-z0-9-_]+}.narinfo", a.handleUploadNarinfo).Methods("POST")

	return router
}

const metricNamespace = "hoardix"

func (a *App) Run() error {
	// parse timestamp to a readable format
	if ts, err := strconv.ParseInt(commitTimestamp, 10, 64); err == nil {
		promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: metricNamespace,
				Name:      "commit_date_timestamp",
				Help:      "hoardix's commit date in unix timestamp",
			},
		).Set(float64(ts))
		commitTimestamp = time.Unix(ts, 0).Format(time.RFC3339)
	}

	promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace:   metricNamespace,
			Name:        "info",
			Help:        "hoardix's build version and commit hash",
			ConstLabels: prometheus.Labels{"version": version, "commit_hash": commitHash},
		},
	).Set(1)

	a.logger.Info().Str("version", version).Str("commit", commitHash).Str("commit_time", commitTimestamp).Str("go_version", runtime.Version()).Msg("starting hoardix")

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

	// signal handler
	ctxSignal, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	listenPort := 5000
	if a.cfg.ListenPort != nil {
		listenPort = *a.cfg.ListenPort
	}
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", listenPort),
		Handler: logHandler(accessHandler(a.initRouter())),
	}
	go func() {
		if err = srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			a.logger.Fatal().Err(err).Msgf("error listening on '%s' for HTTP traffic", srv.Addr)
		}
	}()

	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			// Opt into OpenMetrics to support exemplars.
			EnableOpenMetrics: true,
		},
	))
	metricsListenPort := 9500
	if a.cfg.MetricsListenPort != nil {
		metricsListenPort = *a.cfg.MetricsListenPort
	}
	metricsSrv := &http.Server{
		Addr:    fmt.Sprintf(":%d", metricsListenPort),
		Handler: metricsMux,
	}
	go func() {
		if err = metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			a.logger.Fatal().Err(err).Msgf("error listening on '%s' for metrics", srv.Addr)
		}
	}()

	// wait till signal to shutdown
	<-ctxSignal.Done()

	ctxStopTimeout, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer func() {
		cancel()
	}()

	if err = srv.Shutdown(ctxStopTimeout); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("error shutting down http server: %w", err)
	}
	if err = metricsSrv.Shutdown(ctxStopTimeout); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("error shutting down metrics server: %w", err)
	}

	a.logger.Info().Msg("http servers exited properly")

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

func (a *App) BaseURL() *url.URL {
	var u = *a.cfg.BaseURL.URL
	return &u
}
