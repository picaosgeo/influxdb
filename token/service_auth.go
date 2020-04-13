package token

import (
	"context"

	"github.com/influxdata/influxdb/v2"
	"github.com/influxdata/influxdb/v2/kv"
)

var _ influxdb.AuthorizationService = (*Service)(nil)

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

	var a influxdb.Authorization

	if upd.Status != nil {
		a.Status = *upd.Status
	}
	if upd.Description != nil {
		a.Description = *upd.Description
	}

	now := s.TimeGenerator.Now()
	a.SetUpdatedAt(now)

	var a *influxdb.Authorization
	err = s.kv.Update(ctx, func(tx Tx) error {
		a, err = s.UpdateAuthorization(ctx, tx, id, upd)
		return err
	})
	return a, err
}

func (s *Service) DeleteAuthorization(ctx context.Context, id influxdb.ID) error {
	return s.kv.Update(ctx, func(tx Tx) (err error) {
		return s.deleteAuthorization(ctx, tx, id)
	})
}
