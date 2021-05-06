package httpserver

import (
	"github.com/gorilla/mux"
	"net/http"
	"time"
)

type config struct {
	ServerName string      `yaml:"server_name"`
	Address    string      `yaml:"address" validate:"required"`
	Handler    *mux.Router `yaml:"-"`
	TLS        struct {
		Enable  bool   `yaml:"enable"`
		Version string `yaml:"version" validate:"tls_version"`
	} `yaml:"tls"`
	Timeouts struct {
		Request    string `yaml:"request"`
		Read       string `yaml:"read"`
		ReadHeader string `yaml:"read_header"`
		Write      string `yaml:"write"`
		Idle       string `yaml:"idle"`
	} `yaml:"timeouts"`
	CSRF struct {
		Enable     bool   `yaml:"enable"`
		Key        string `yaml:"key" validate:"csrf_key"`
		FieldName  string `yaml:"field_name" validate:"csrf_name"`
		CookieName string `yaml:"cookie_name" validate:"csrf_name"`
		Secure     bool   `yaml:"secure"`
		HTTPOnly   bool   `yaml:"http_only"`
		SameSite   string `yaml:"same_site" validate:"csrf_same_site"`
		Path       string `yaml:"path"`
	} `yaml:"csrf"`
}

func New() *config {
	return &config{}
}

func (c *config) handler() http.Handler {
	requestTimeout, err := time.ParseDuration(c.Timeouts.Request)
	if err != nil {
		return nil
	}
	if requestTimeout > 0 {
		return http.TimeoutHandler(c.Handler, requestTimeout, "")
	}
	return c.Handler
}

func (c *config) Server() *http.Server {

	readTimeout, err := time.ParseDuration(c.Timeouts.Request)
	if err != nil {
		return nil
	}
	readHeaderTimeout, err := time.ParseDuration(c.Timeouts.Request)
	if err != nil {
		return nil
	}
	writeTimeout, err := time.ParseDuration(c.Timeouts.Request)
	if err != nil {
		return nil
	}
	idleTimeout, err := time.ParseDuration(c.Timeouts.Request)
	if err != nil {
		return nil
	}

	return &http.Server{
		Addr:              c.Address,
		Handler:           c.handler(),
		TLSConfig:         c.tlsConfig(),
		ReadTimeout:       readTimeout,
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
}
