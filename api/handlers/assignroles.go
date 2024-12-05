package handlers

import (
	"context"
)

func (s Server) AssignRoles(
	_ context.Context, request AssignRolesRequestObject,
) (AssignRolesResponseObject, error) {
	err := s.db.User.UpdateOneID(request.Id).
		AddRoleIDs(*request.Body...).Exec(context.Background())
	if err != nil {
		return nil, err
	}
	return AssignRoles204Response{}, nil
}
