package api

import (
	"context"

	"github.com/eidng8/go-ent/softdelete"

	"github.com/eidng8/go-attr-rbac/ent"
)

func (s Server) DeleteUser(
	ctx context.Context, request DeleteUserRequestObject,
) (DeleteUserResponseObject, error) {
	_, err := s.db.Transaction(
		context.Background(),
		func(ctx context.Context, tx *ent.Tx) (interface{}, error) {
			return nil, tx.User.DeleteOneID(request.Id).Exec(
				softdelete.NewSoftDeleteQueryContext(
					request.Params.Trashed, context.Background(),
				),
			)
		},
	)
	if err != nil {
		return nil, err
	}
	return DeleteUser204Response{}, nil
}
