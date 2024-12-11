package handlers

import (
	"context"

	"github.com/oapi-codegen/runtime/types"

	"github.com/eidng8/go-attr-rbac/ent/user"
)

// HintUsers returns a short list of users.
//
// Endpoint: GET /q/users
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
		list[i] = UserList{
			Id:       row.ID,
			Username: row.Username,
		}
		if nil != row.Email && "" != *row.Email {
			email := types.Email(*row.Email)
			list[i].Email = &email
		}
	}
	return list, nil
}
