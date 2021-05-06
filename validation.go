package httpserver

import (
	"github.com/go-playground/validator"
	"regexp"
)

func validateCSRFSameSite(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	sameSiteMode := map[string]bool{
		"strict":  true,
		"lax":     true,
		"none":    true,
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

func validateTLS(fl validator.FieldLevel) bool {
	tlsVersions := map[string]bool{
		"tls1.3": true,
		"tls1.2": true,
		"tls1.1": true,
	}

	return tlsVersions[fl.Field().String()]
}
