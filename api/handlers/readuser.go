package handlers

import (
	"context"

	"github.com/eidng8/go-ent/softdelete"
	"github.com/oapi-codegen/runtime/types"

	"github.com/eidng8/go-attr-rbac/ent/user"
)

func (s Server) ReadUser(
	ctx context.Context, request ReadUserRequestObject,
) (ReadUserResponseObject, error) {
	u, err := s.db.User.Query().Where(user.ID(request.Id)).Only(
		softdelete.NewSoftDeleteQueryContext(
			request.Params.Trashed, context.Background(),
		),
	)
	if err != nil {
		return nil, err
	}
	email := types.Email(u.Email)
	return ReadUser200JSONResponse{
		Id:        u.ID,
		Username:  u.Username,
		Email:     &email,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
		DeletedAt: u.DeletedAt,
	}, nil
}
