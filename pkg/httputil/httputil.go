package httputil

import (
	"net/http"

	"github.com/rs/zerolog/hlog"
)

type Error struct {
	Err        error
	Msg        string
	StatusCode int
}

func WriteError(w http.ResponseWriter, r *http.Request, err *Error) {
	if err.Err != nil {
		hlog.FromRequest(r).Error().Err(err.Err).Msg("")
	}
	statusCode := err.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusInternalServerError
	}
	w.WriteHeader(statusCode)
	if err.Msg != "" {
		_, _ = w.Write([]byte(err.Msg))
	}
}
