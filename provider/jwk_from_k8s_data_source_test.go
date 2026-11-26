package provider

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchJwksToken(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openid/v1/jwks" || r.Header.Get("Authorization") != "Bearer secret" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"kind":"Status"}`))
			return
		}
		w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"a"},{"kty":"RSA","kid":"b"}]}`))
	}))
	defer srv.Close()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))

	keys, err := fetchJwks(context.Background(), srv.URL, caPEM, nil, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || string(keys[0]) != `{"kty":"RSA","kid":"a"}` {
		t.Fatalf("unexpected keys: %s", keys)
	}

	if _, err := fetchJwks(context.Background(), srv.URL, caPEM, nil, "wrong"); err == nil {
		t.Fatal("expected error on HTTP 401")
	}
}

func TestExecToken(t *testing.T) {
	e := &ExecModel{
		APIVersion: "client.authentication.k8s.io/v1",
		Command:    "sh",
		Args:       []string{"-c", `printf '{"status":{"token":"%s-%s"}}' "$TOK" "$(echo "$KUBERNETES_EXEC_INFO" | grep -c ExecCredential)"`},
		Env:        map[string]string{"TOK": "secret"},
	}
	token, err := execToken(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	if token != "secret-1" {
		t.Fatalf("unexpected token %q", token)
	}

	e.Args = []string{"-c", `echo '{"status":{}}'`}
	if _, err := execToken(context.Background(), e); err == nil {
		t.Fatal("expected error on missing token")
	}
	e.Args = []string{"-c", "echo boom >&2; exit 1"}
	if _, err := execToken(context.Background(), e); err == nil {
		t.Fatal("expected error on failing command")
	}
}
