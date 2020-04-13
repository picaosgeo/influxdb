package token

import (
	"github.com/influxdata/influxdb/v2"
	"go.uber.org/zap"
)

type AuthLogger struct {
	logger      *zap.Logger
	authService influxdb.AuthorizationService
}

// NewAuthLogger returns a logging service middleware for the Authorization Service.
func NewAuthLogger(log *zap.Logger, s influxdb.AuthorizationService) *AuthLogger {
	return &AuthLogger{
		logger:      log,
		authService: s,
	}
}
