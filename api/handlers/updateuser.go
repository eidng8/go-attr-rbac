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
	res := UpdateUser200JSONResponse{
		Id:        u.ID,
		Username:  u.Username,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
	if nil != u.Email && "" != *u.Email {
		email := types.Email(*u.Email)
		res.Email = &email
	}
	return res, nil
}
