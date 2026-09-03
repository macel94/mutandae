package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFaviconEndpointsServeTheBrandMark(t *testing.T) {
	t.Parallel()
	handler := testHandler(t)
	cases := map[string]string{
		"/favicon.ico": "image/x-icon",
		"/favicon.svg": "image/svg+xml",
	}
	for path, contentType := range cases {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want %d", path, recorder.Code, http.StatusOK)
		}
		if got := recorder.Header().Get("Content-Type"); got != contentType {
			t.Errorf("GET %s Content-Type = %q, want %q", path, got, contentType)
		}
		if recorder.Body.Len() == 0 {
			t.Errorf("GET %s returned an empty body", path)
		}
	}
}

func TestPagesLinkFavicon(t *testing.T) {
	t.Parallel()
	handler := testHandler(t)
	for _, path := range []string{"/", "/configuration"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want %d", path, recorder.Code, http.StatusOK)
			continue
		}
		body := recorder.Body.String()
		for _, want := range []string{`rel="icon"`, `href="/favicon.ico"`, `href="/static/favicon.svg"`} {
			if !strings.Contains(body, want) {
				t.Errorf("GET %s body does not contain %q", path, want)
			}
		}
	}
}
