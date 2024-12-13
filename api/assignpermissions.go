package api

import (
	"context"
	"net/http"

	"github.com/eidng8/go-attr-rbac/ent"
)

// AssignPermissions assigns permissions to a role.
//
// Endpoint: POST /role/{id}/permissions
func (s Server) AssignPermissions(
	_ context.Context, request AssignPermissionsRequestObject,
) (AssignPermissionsResponseObject, error) {
	_, err := s.db.Transaction(
		context.Background(),
		func(qc context.Context, tx *ent.Tx) (interface{}, error) {
			return nil, tx.Role.UpdateOneID(request.Id).
				AddPermissionIDs(*request.Body...).Exec(qc)
		},
	)
	if err != nil {
		if ent.IsForeignKeyError(err) {
			return AssignPermissions400JSONResponse{
				N400JSONResponse: N400JSONResponse{
					Code:   http.StatusBadRequest,
					Errors: &msgInvalidAssignment,
					Status: msgError,
				},
			}, nil
		}
		Log.Debugf("AssignPermissions error: %v", err)
		return nil, err
	}
	return AssignPermissions204Response{}, nil
}
