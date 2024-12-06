package handlers

import (
	"context"

	"github.com/oapi-codegen/runtime/types"

	"github.com/eidng8/go-attr-rbac/ent"
)

// UpdateUser updates a user.
//
// Endpoint: PATCH /user/{id}
func (s Server) UpdateUser(
	ctx context.Context, request UpdateUserRequestObject,
) (UpdateUserResponseObject, error) {
	r, err := s.db.Transaction(
		context.Background(),
		func(ctx context.Context, tx *ent.Tx) (interface{}, error) {
			r, err := tx.User.UpdateOneID(request.Id).
				SetEmail(string(*request.Body.Email)).
				Save(ctx)
			if err != nil {
				return nil, err
			}
			return r, nil
		},
	)
	if err != nil {
		return nil, err
	}
	u := r.(*ent.User)
	email := types.Email(u.Email)
	return UpdateUser200JSONResponse{
		Id:        u.ID,
		Username:  u.Username,
		Email:     &email,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}, nil
}
