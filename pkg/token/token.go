package token

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/hlog"
	"gopkg.in/yaml.v3"
)

type Handler struct {
	cfg []Config
}

func New(cfg []Config) *Handler {
	return &Handler{cfg: cfg}
}

type contextKey uint8

const (
	contextKeyPermission contextKey = iota
)

func ContextWithPermission(ctx context.Context, p Permission) context.Context {
	return context.WithValue(ctx, contextKeyPermission, p)
}

func PermissionFromContext(ctx context.Context) Permission {
	v := ctx.Value(contextKeyPermission)
	p, ok := v.(Permission)
	if !ok {
		return PermissionAnonymous
	}
	return p
}

func (h *Handler) getPermission(r *http.Request) (perm Permission) {
	log := hlog.FromRequest(r).Debug()
	defer func() {
		log.Str("permission", perm.String()).Msg("authentication check")
	}()

	// get cache name
	vars := mux.Vars(r)
	cacheName := vars["cache_name"]
	if cacheName == "" {
		return PermissionAnonymous
	}
	log = log.Str("cache_name", cacheName)

	// no valid token found
	authHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")
	if len(authHeader) != 2 {
		return PermissionAnonymous
	}

	authToken := Token(authHeader[1])
	for _, c := range h.cfg {
		if c.Static != nil {
			matchedToken := false
			for _, t := range c.Static.Tokens {
				if t == authToken {
					matchedToken = true
					break
				}
			}
			if !matchedToken {
				continue
			}

			// iterate through mappings
			for _, m := range c.Static.Mappings {
				if !m.matchesCacheName(cacheName) {
					continue
				}
				if perm < m.Permission {
					perm = m.Permission
				}
			}
		}

	}

	return perm

}

func (h *Handler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := h.getPermission(r)
		next.ServeHTTP(w, r.WithContext(ContextWithPermission(r.Context(), p)))
	})
}

type Config struct {
	Static *ConfigStatic `yaml:"static,omitempty"`
}

type ConfigStatic struct {
	Tokens   []Token          `yaml:"tokens,omitempty"`
	Mappings []ConfigMappings `yaml:"mappings,omitempty"`
}

type ConfigMappings struct {
	Permission Permission `yaml:"permission,omitempty"`
	Caches     []string   `yaml:"caches,omitempty"`
}

func (m *ConfigMappings) matchesCacheName(cacheName string) bool {
	for _, name := range m.Caches {
		if name == cacheName {
			return true
		}
	}

	return false
}

type Permission int8

const (
	PermissionAnonymous Permission = iota
	PermissionRead
	PermissionWrite
	PermissionAdmin
)

var permissionByString = map[string]Permission{
	"anonymous": PermissionAnonymous,
	"read":      PermissionRead,
	"write":     PermissionWrite,
	"admin":     PermissionAdmin,
}

func (p *Permission) UnmarshalYAML(value *yaml.Node) error {
	var stringValue string
	if err := value.Decode(&stringValue); err != nil {
		return err
	}

	if stringValue == "" {
		*p = PermissionAnonymous
		return nil
	}

	if v, ok := permissionByString[stringValue]; ok {
		*p = v
		return nil
	}

	return fmt.Errorf("invalid permission '%s'", stringValue)
}

func (p Permission) String() string {
	for str, permission := range permissionByString {
		if permission == p {
			return str
		}
	}
	return ""
}

func (p Permission) MarshalYAML() (interface{}, error) {
	if str := p.String(); str != "" {
		return str, nil
	}

	return nil, fmt.Errorf("unknown permission %v", p)
}

type Token string

func (t Token) MarshalYAML() (interface{}, error) {
	return "<redacted>", nil
}
