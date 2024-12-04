package api

import (
	"context"

	"github.com/oapi-codegen/runtime/types"

	"github.com/eidng8/go-attr-rbac/ent/user"
)

func (s Server) HintUsers(
	_ context.Context, request HintUsersRequestObject,
) (HintUsersResponseObject, error) {
	rows, err := s.db.User.Query().Limit(s.hintSize).
		Select(user.FieldID, user.FieldUsername, user.FieldEmail).
		Where(
			user.Or(
				user.UsernameHasPrefix(request.Params.Q),
				user.EmailHasPrefix(request.Params.Q),
			),
		).
		All(context.Background())
	if err != nil {
		return nil, err
	}
	list := make(HintUsers200JSONResponse, len(rows))
	for i, row := range rows {
		email := types.Email(row.Email)
		list[i] = UserList{
			Id:       row.ID,
			Username: row.Username,
			Email:    &email,
		}
	}
	return list, nil
}
