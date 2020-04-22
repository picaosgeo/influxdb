package token_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi"
	"github.com/influxdata/influxdb/v2"
	ihttp "github.com/influxdata/influxdb/v2/http"
	"github.com/influxdata/influxdb/v2/inmem"
	"github.com/influxdata/influxdb/v2/kv"
	itesting "github.com/influxdata/influxdb/v2/testing"
	"github.com/influxdata/influxdb/v2/token"
	"go.uber.org/zap/zaptest"
)

func initAuthorizationService(f itesting.AuthorizationFields, t *testing.T) (influxdb.AuthorizationService, string, func()) {
	t.Helper()

	s, stCloser, err := NewTestInmemStore(t)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := token.NewStore(s)
	if err != nil {
		t.Fatal(err)
	}

	svc := token.NewService(storage)

	ctx := context.Background()
	for _, u := range f.Authorizations {
		if err := svc.CreateAuthorization(ctx, u); err != nil {
			t.Fatalf("failed to populate authorizations")
		}
	}

	handler := token.NewHTTPAuthHandler(zaptest.NewLogger(t), svc)
	r := chi.NewRouter()
	r.Mount("/api/v2/authorizations", handler)
	server := httptest.NewServer(r)
	httpClient, err := ihttp.NewHTTPClient(server.URL, "", false)
	if err != nil {
		t.Fatal(err)
	}

	client := token.AuthorizationClientService{
		Client: httpClient,
	}

	return &client, "http_token", func() {
		server.Close()
		stCloser()
	}

}

func NewTestInmemStore(t *testing.T) (kv.Store, func(), error) {
	return inmem.NewKVStore(), func() {}, nil
}

func TestAuthorizationService(t *testing.T) {
	itesting.AuthorizationService(initAuthorizationService, t)
}