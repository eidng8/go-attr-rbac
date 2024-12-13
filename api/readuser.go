package api

import (
	"context"

	"github.com/eidng8/go-ent/softdelete"
	"github.com/oapi-codegen/runtime/types"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/user"
)

// ReadUser reads a user.
//
// Endpoint: GET /user/{id}
func (s Server) ReadUser(
	ctx context.Context, request ReadUserRequestObject,
) (ReadUserResponseObject, error) {
	u, err := s.db.User.Query().Where(user.ID(request.Id)).Only(
		softdelete.NewSoftDeleteQueryContext(
			request.Params.Trashed, context.Background(),
		),
	)
	if err != nil {
		if ent.IsNotFound(err) {
			return ReadUser404JSONResponse{}, nil
		}
		Log.Debugf("ReadUser error: %v", err)
		return nil, err
	}
	res := ReadUser200JSONResponse{
		Id:        u.ID,
		Username:  u.Username,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
		DeletedAt: u.DeletedAt,
	}
	if nil != u.Email && "" != *u.Email {
		email := types.Email(*u.Email)
		res.Email = &email
	}
	return res, nil
}
