package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCLIAdminBearerToken(t *testing.T) {
	secret := strings.Repeat("a", 48)
	t.Setenv("ADMIN_TOKEN", secret)
	h := saSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sessionFromCtx(r.Context()).Role != RoleSuperAdmin {
			t.Fatal("bearer token did not receive admin role")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tc := range []struct {
		name, header string
		want         int
	}{
		{"valid", "Bearer " + secret, http.StatusNoContent},
		{"wrong", "Bearer " + strings.Repeat("b", 48), http.StatusUnauthorized},
		{"short", "Bearer a", http.StatusUnauthorized},
		{"empty", "", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("got status %d, want %d", w.Code, tc.want)
			}
		})
	}
}
