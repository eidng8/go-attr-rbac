package api

import (
	"context"

	"github.com/eidng8/go-attr-rbac/ent"
)

func (s Server) DeletePermission(
	ctx context.Context, request DeletePermissionRequestObject,
) (DeletePermissionResponseObject, error) {
	_, err := s.db.Transaction(
		context.Background(),
		func(qc context.Context, tx *ent.Tx) (interface{}, error) {
			if e := tx.Permission.DeleteOneID(request.Id).Exec(ctx); e != nil {
				return nil, e
			}
			return nil, nil
		},
	)
	if err != nil {
		return nil, err
	}
	return DeletePermission204Response{}, nil
}
