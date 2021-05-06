package httpserver

import (
	"fmt"
	"github.com/gorilla/mux"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNew(t *testing.T) {
	server := New()
	server.Address = ":8080"
	server.Handler = mux.NewRouter()
	server.TLS.Enable = true
	server.TLS.Version = "tls_1.3"
	server.Timeouts.Request = "5s"
	server.Timeouts.Idle = "120s"
	server.Timeouts.Read = "10s"
	server.Timeouts.ReadHeader = "5s"
	server.Timeouts.Write = "10s"

	srv := server.Server()
	if fmt.Sprintf("%T", srv) != fmt.Sprintf("%T", &http.Server{}) {
		t.Fatalf("Expected returned value of Server() to be type *http.Server, instead got %T", srv)
	}
}

func TestHandler(t *testing.T) {
	server := New()
	server.Address = ":8080"
	server.Handler = mux.NewRouter()
	server.TLS.Enable = true
	server.TLS.Version = "tls_1.3"
	server.Timeouts.Request = "5s"
	server.Timeouts.Idle = "120s"
	server.Timeouts.Read = "10s"
	server.Timeouts.ReadHeader = "5s"
	server.Timeouts.Write = "10s"

	srv := server.Server()
	if fmt.Sprintf("%T", srv) != fmt.Sprintf("%T", &http.Server{}) {
		t.Fatalf("Expected returned value of Server() to be type *http.Server, instead got %T", srv)
	}

	server.Handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("success"))
	})

	rr := httptest.NewRecorder()

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("encounted an error: %v", err.Error())
	}

	srv.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Handler returned unexpected status code; expected Status OK (200) but got %v (%v)", http.StatusText(rr.Code), rr.Code)
	}
	if rr.Body.String() != "success" {
		t.Errorf("Returned value to be \"success\", instead got \"%v\"", rr.Body.String())
	}
}

func TestConfig_Yaml(t *testing.T) {
	data, err := ioutil.ReadFile("server.yaml")
	if err != nil {
		t.Fatalf("Error reading config file \"server.yaml.example\", %v ", err.Error())
	}
	server := New()
	err = server.Yaml(data)
	if err != nil {
		t.Fatalf("Error setting config from file, %v ", err.Error())
	}
}
