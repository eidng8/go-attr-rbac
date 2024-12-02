package api

import (
	"context"

	"github.com/eidng8/go-attr-rbac/ent"
)

func (s Server) DeleteRole(
	ctx context.Context, request DeleteRoleRequestObject,
) (DeleteRoleResponseObject, error) {
	_, err := s.db.Transaction(
		context.Background(),
		func(ctx context.Context, tx *ent.Tx) (interface{}, error) {
			return nil, tx.Role.DeleteOneID(request.Id).Exec(ctx)
		},
	)
	if err != nil {
		return nil, err
	}
	return DeleteRole204Response{}, nil
}
