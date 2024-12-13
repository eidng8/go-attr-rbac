package handlers

import (
	"context"
	"net/http"

	"github.com/oapi-codegen/runtime/types"

	"github.com/eidng8/go-attr-rbac/ent"
)

// UpdateUser updates a user.
//
// Endpoint: PATCH /user/{id}
func (s Server) UpdateUser(
	ctx context.Context, request UpdateUserRequestObject,
) (UpdateUserResponseObject, error) {
	if nil == request.Body.Email && nil == request.Body.Attr &&
		(nil == request.Body.Roles || len(*request.Body.Roles) == 0) {
		return UpdateUser422JSONResponse{
			N422JSONResponse: N422JSONResponse{
				Code:   http.StatusUnprocessableEntity,
				Status: msgError,
				Errors: &msgEmptyRequest,
			},
		}, nil
	}
	r, err := s.db.Transaction(
		context.Background(),
		func(ctx context.Context, tx *ent.Tx) (interface{}, error) {
			r := tx.User.UpdateOneID(request.Id)
			if request.Body.Email != nil {
				r.SetEmail(string(*request.Body.Email))
			}
			if nil != request.Body.Roles && len(*request.Body.Roles) > 0 {
				r.ClearRoles()
				r.AddRoleIDs(*request.Body.Roles...)
			}
			if request.Body.Attr != nil {
				r.SetAttr(userAttrToMap(*request.Body.Attr))
			}
			return r.Save(ctx)
		},
	)
	if err != nil {
		if ent.IsNotFound(err) {
			return UpdateUser404JSONResponse{
				N404JSONResponse: N404JSONResponse{
					Code:   http.StatusNotFound,
					Status: msgError,
					Errors: &msgNotFound,
				},
			}, nil
		}
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
	if nil != u.Attr {
		res.Attr = userAttrFromMap(*u.Attr)
	}
	return res, nil
}
