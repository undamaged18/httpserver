package httpserver

import (
	"crypto/tls"
	"github.com/go-playground/validator"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"
	"net/http"
	"regexp"
	"time"
)

type config struct {
	ServerName string      `yaml:"server_name"`
	Address    string      `yaml:"address" validate:"required"`
	Handler    *mux.Router `yaml:"-"`
	TLS        struct {
		Enable  bool   `yaml:"enable"`
		Version string `yaml:"version"`
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

func validateCSRFSameSite(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	sameSiteMode := map[string]bool{
		"strict": true,
		"lax": true,
		"none": true,
		"default": true,
	}
	return sameSiteMode[value]
}

func validateCSRFName(fl validator.FieldLevel) bool {
	re := regexp.MustCompile("^[A-Za-z0-9_-]+$")
	matches := re.FindAllString(fl.Field().String(), -1)
	return len(matches) == 1
}

func validateCSRFKey(fl validator.FieldLevel) bool {
	return len([]byte(fl.Field().String())) != 32
}

func (c *config) Yaml(data []byte) error {
	err := yaml.Unmarshal(data, c)
	if err != nil {
		return err
	}
	validate := validator.New()
	_ = validate.RegisterValidation("csrf_same_site", validateCSRFSameSite)
	_= validate.RegisterValidation("csrf_name", validateCSRFName)
	_= validate.RegisterValidation("csrf_key", validateCSRFKey)

	return validate.Struct(c)
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

func (c *config) csrfConfig() func(handler http.Handler) http.Handler {
	sameSiteMode := map[string]csrf.SameSiteMode{
		"strict": csrf.SameSiteStrictMode,
		"lax": csrf.SameSiteLaxMode,
		"none": csrf.SameSiteNoneMode,
		"default": csrf.SameSiteDefaultMode,
	}
	if c.CSRF.Enable {
		return csrf.Protect(
			[]byte(c.CSRF.Key),
			csrf.CookieName(c.CSRF.CookieName),
			csrf.FieldName(c.CSRF.FieldName),
			csrf.HttpOnly(c.CSRF.HTTPOnly),
			csrf.Secure(c.CSRF.Secure),
			csrf.SameSite(sameSiteMode[c.CSRF.SameSite]),
			csrf.Path(c.CSRF.Path),
		)
	}
	return nil
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

func (c *config) tlsConfig() *tls.Config {
	if c.TLS.Enable {
		tlsVersions := map[string]uint16{
			"tls_1.3": tls.VersionTLS13,
			"tls_1.2": tls.VersionTLS12,
			"tls_1.1": tls.VersionTLS11,
		}
		return &tls.Config{
			ServerName:               c.ServerName,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			CipherSuites:             c.cipherSuites(),
			PreferServerCipherSuites: true,
			MinVersion:               tlsVersions[c.TLS.Version],
		}
	}
	return nil
}

func (c *config) cipherSuites() []uint16 {
	if c.TLS.Version != "tls_1.3" {
		return []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		}
	}
	return nil
}
