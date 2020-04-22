package token

import (
	"context"
	"fmt"
	"time"

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

var _ influxdb.AuthorizationService = (*AuthLogger)(nil)

func (l *AuthLogger) CreateAuthorization(ctx context.Context, a *influxdb.Authorization) (err error) {
	defer func(start time.Time) {
		dur := zap.Duration("took", time.Since(start))
		if err != nil {
			l.logger.Error("failed to create authorization", zap.Error(err), dur)
			return
		}
		l.logger.Debug("authorization create", dur)
	}(time.Now())
	return l.authService.CreateAuthorization(ctx, a)
}

func (l *AuthLogger) FindAuthorizationByID(ctx context.Context, id influxdb.ID) (a *influxdb.Authorization, err error) {
	defer func(start time.Time) {
		dur := zap.Duration("took", time.Since(start))
		if err != nil {
			msg := fmt.Sprintf("failed to find authorization with ID %v", id)
			l.logger.Error(msg, zap.Error(err), dur)
			return
		}
		l.logger.Debug("auth find by ID", dur)
	}(time.Now())
	return l.authService.FindAuthorizationByID(ctx, id)
}

func (l *AuthLogger) FindAuthorization(ctx context.Context, t string) (a *influxdb.Authorization, err error) {
	defer func(start time.Time) {
		dur := zap.Duration("took", time.Since(start))
		if err != nil {
			l.logger.Error("failed to find authorization mwith token", zap.Error(err), dur)
			return
		}
		l.logger.Debug("auth find", dur)

	}(time.Now())
	return l.authService.FindAuthorizationByToken(ctx, t)
}

func (l *AuthLogger) FindAuthorizations(ctx context.Context, filter influxdb.AuthorizationFilter, opt ...FindOptions) ([]*Authorization, int, error) {
	return nil, 0, nil
}

func (l *AuthLogger) UpdateAuthorization(ctx context.Context, id influxdb.ID, udp *influxdb.AuthorizationUpdate) (*Authorization, error) {
	return nil, nil
}

func (l *AuthLogger) DeleteAuthorization(ctx context.Context, id influxdb.ID) error {
	return nil
}
