package handlers

import (
	"context"

	"github.com/eidng8/go-attr-rbac/ent"
)

func (s Server) DeletePersonalToken(
	ctx context.Context, request DeletePersonalTokenRequestObject,
) (DeletePersonalTokenResponseObject, error) {
	_, err := s.db.Transaction(
		context.Background(),
		func(ctx context.Context, tx *ent.Tx) (interface{}, error) {
			return nil, tx.PersonalToken.DeleteOneID(request.Id).Exec(ctx)
		},
	)
	if err != nil {
		return nil, err
	}
	return DeletePersonalToken204Response{}, nil
}
