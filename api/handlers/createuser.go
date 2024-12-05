package handlers

import (
	"context"
	"fmt"

	"github.com/oapi-codegen/runtime/types"

	"github.com/eidng8/go-attr-rbac/ent"
)

func (s Server) CreateUser(
	ctx context.Context, request CreateUserRequestObject,
) (CreateUserResponseObject, error) {
	u, err := s.db.Transaction(
		context.Background(),
		func(qc context.Context, tx *ent.Tx) (interface{}, error) {
			p, err := tx.User.Create().
				SetUsername(request.Body.Username).
				SetEmail(string(*request.Body.Email)).
				Save(ctx)
			if err != nil {
				return nil, err
			}
			return p, nil
		},
	)
	if err != nil {
		return nil, err
	}
	user, ok := u.(*ent.User)
	if !ok {
		return nil, fmt.Errorf("failed to create user: %T", u)
	}
	email := types.Email(user.Email)
	return CreateUser200JSONResponse{
		Id:        user.ID,
		Username:  user.Username,
		Email:     &email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}, nil
}
