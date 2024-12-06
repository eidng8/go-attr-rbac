package handlers

import (
	"context"
)

// AssignPermissions assigns permissions to a role.
//
// Endpoint: POST /role/{id}/permissions
func (s Server) AssignPermissions(
	_ context.Context, request AssignPermissionsRequestObject,
) (AssignPermissionsResponseObject, error) {
	err := s.db.Role.UpdateOneID(request.Id).
		AddPermissionIDs(*request.Body...).Exec(context.Background())
	if err != nil {
		return nil, err
	}
	return AssignPermissions204Response{}, nil
}
