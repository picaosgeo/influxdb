package token

import (
	"context"
	"time"

	"github.com/influxdata/influxdb/v2"
	"github.com/influxdata/influxdb/v2/kv"
)

var _ influxdb.AuthorizationService = (*Service)(nil)

// move to end
func (s *Service) uniqueAuthToken(ctx context.Context, tx kv.Tx, a *influxdb.Authorization) error {
	err := s.store.unique(ctx, tx, authIndex, authIndexKey(a.Token))
	if err == kv.NotUniqueError {
		// by returning a generic error we are trying to hide when
		// a token is non-unique.
		return influxdb.ErrUnableToCreateToken
	}
	// otherwise, this is some sort of internal server error and we
	// should provide some debugging information.
	return err
}

func (s *Service) CreateAuthorization(ctx context.Context, a *influxdb.Authorization) error {
	// // todo (al): we also need to check if the user has write permissions
	// can the auth middleware layer do this?
	// if u, err := s.findUserByID(ctx, tx, a.UserID); err != nil {
	// 	return influxdb.ErrUnableToCreateToken
	// }

	if err := a.Valid(); err != nil {
		return &influxdb.Error{
			Err: err,
		}
	}

	// TODO (al) put this somewhere
	if err := s.uniqueAuthToken(ctx, tx, a); err != nil {
		return err
	}

	if a.Token == "" {
		token, err := s.TokenGenerator.Token()
		if err != nil {
			return &influxdb.Error{
				Err: err,
			}
		}
		a.Token = token
	}

	return nil
}

func (s *Service) FindAuthorizationByID(ctx context.Context, id influxdb.ID) (*influxdb.Authorization, error) {
	var a *influxdb.Authorization
	err := s.store.View(ctx, func(tx kv.Tx) error {
		auth, err := s.store.GetAuthorizationByID(ctx, tx, id)
		if err != nil {
			return nil
		}

		a = auth
		return nil
	})

	if err != nil {
		return nil, err
	}

	return a, nil
}

// FindAuthorizationByToken returns a authorization by token for a particular authorization.
func (s *Service) FindAuthorizationByToken(ctx context.Context, n string) (*influxdb.Authorization, error) {
	var a *influxdb.Authorization
	err := s.store.View(ctx, func(tx kv.Tx) error {
		auth, err := s.store.GetAuthorizationByToken(ctx, tx, n)
		if err != nil {
			return err
		}

		a = auth

		return nil
	})

	if err != nil {
		return nil, err
	}

	return a, nil
}

// FindAuthorizations retrives all authorizations that match an arbitrary authorization filter.
// Filters using ID, or Token should be efficient.
// Other filters will do a linear scan across all authorizations searching for a match.
func (s *Service) FindAuthorizations(ctx context.Context, filter influxdb.AuthorizationFilter, opt ...influxdb.FindOptions) ([]*influxdb.Authorization, int, error) {
	if filter.ID != nil {
		var a *influxdb.Authorization
		err := s.store.View(ctx, func(tx kv.Tx) error {
			a, e := s.store.GetAuthorizationByID(ctx, tx, *filter.ID)
			if e != nil {
				return e
			}
		})
		if err != nil {
			return nil, 0, &influxdb.Error{
				Err: err,
			}
		}

		return []*influxdb.Authorization{a}, 1, nil
	}

	if filter.Token != nil {
		var a *influxdb.Authorization
		err := s.store.View(ctx, func(tx kv.Tx) error {
			a, e := s.store.GetAuthorizationByToken(ctx, tx, *filter.Token)
			if e != nil {
				return nil
			}
		})
		if err != nil {
			return nil, 0, &influxdb.Error{
				Err: err,
			}
		}

		return []*influxdb.Authorization{a}, 1, nil
	}

	as := []*influxdb.Authorization{}
	err := s.store.View(ctx, func(tx kv.Tx) error {
		auths, err := s.store.ListAuthorizations(ctx, tx, filter)
		if err != nil {
			return err
		}
		as = auths
		return nil
	})

	if err != nil {
		return nil, 0, &influxdb.Error{
			Err: err,
		}
	}

	return as, len(as), nil
}

// UpdateAuthorization updates the status and description if available.
func (s *Service) UpdateAuthorization(ctx context.Context, id influxdb.ID, upd *influxdb.AuthorizationUpdate) (*influxdb.Authorization, error) {
	err := s.store.View(ctx, func(tx kv.Tx) error {
		auth, err := s.store.GetAuthorizationByID(ctx, tx, id)
		if err != nil {
			return err
		}
	})
	if err != nil {
		return nil, err // influxdb error?
	}

	var a *influxdb.Authorization

	if upd.Status != nil {
		a.Status = *upd.Status
	}
	if upd.Description != nil {
		a.Description = *upd.Description
	}

	a.SetUpdatedAt(time.Now())

	err = s.store.Update(ctx, func(tx kv.Tx) error {
		e := s.store.UpdateAuthorization(ctx, tx, a)
		return e
	})
	return a, err
}

func (s *Service) DeleteAuthorization(ctx context.Context, id influxdb.ID) error {
	return s.store.Update(ctx, func(tx kv.Tx) (err error) {
		return s.store.DeleteAuthorization(ctx, tx, id)
	})
}
