package httpserver

import (
	"crypto/tls"
	"github.com/go-playground/validator"
	"github.com/gorilla/csrf"
	"gopkg.in/yaml.v3"
	"net/http"
)

func (c *config) Yaml(data []byte) error {
	err := yaml.Unmarshal(data, c)
	if err != nil {
		return err
	}
	validate := validator.New()
	_ = validate.RegisterValidation("csrf_same_site", validateCSRFSameSite)
	_ = validate.RegisterValidation("csrf_name", validateCSRFName)
	_ = validate.RegisterValidation("csrf_key", validateCSRFKey)
	_ = validate.RegisterValidation("tls_version", validateTLS)
	return validate.Struct(c)
}

func (c *config) csrfConfig() func(handler http.Handler) http.Handler {
	sameSiteMode := map[string]csrf.SameSiteMode{
		"strict":  csrf.SameSiteStrictMode,
		"lax":     csrf.SameSiteLaxMode,
		"none":    csrf.SameSiteNoneMode,
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

func (c *config) tlsConfig() *tls.Config {
	if c.TLS.Enable {
		tlsVersions := map[string]uint16{
			"tls1.3": tls.VersionTLS13,
			"tls1.2": tls.VersionTLS12,
			"tls1.1": tls.VersionTLS11,
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
	if c.TLS.Version != "tls1.3" {
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
