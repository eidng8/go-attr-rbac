package handlers

import (
	"context"

	"github.com/eidng8/go-attr-rbac/ent"
)

func (s Server) RestoreUser(
	ctx context.Context, request RestoreUserRequestObject,
) (RestoreUserResponseObject, error) {
	_, err := s.db.Transaction(
		context.Background(),
		func(ctx context.Context, tx *ent.Tx) (interface{}, error) {
			return nil, tx.User.UpdateOneID(request.Id).ClearDeletedAt().
				Exec(ctx)
		},
	)
	if err != nil {
		return nil, err
	}
	return RestoreUser204Response{}, nil
}
