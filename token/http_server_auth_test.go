package token_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi"
	"github.com/influxdata/influxdb/v2"
	itesting "github.com/influxdata/influxdb/v2/testing"
	"github.com/influxdata/influxdb/v2/token"
	"go.uber.org/zap/zaptest"
)

func initAuthorizationService(f itesting.AuthorizationFields, t *testing.T) (*influxdb.AuthorizationService, string, func()) {
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

	handler := token.NewHTTPAuthorizationHandler(zaptest.NewLogger(t), svc, nil, nil)
	r := chi.NewRouter()
	r.Mount(handler.Prefix(), handler)
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

func TestAuthorizationService(t *testing.T) {
	itesting.AuthorizationService(initBucketHttpService, t, itesting.WithoutHooks())
}
