package token

import "github.com/influxdata/influxdb/v2"

type Service struct {
	store *Store
}

func NewService(st *Store) influxdb.AuthorizationService {
	return &Service{
		store: st,
	}
}
