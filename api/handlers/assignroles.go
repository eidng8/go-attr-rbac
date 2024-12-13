package handlers

import (
	"context"
	"net/http"

	"github.com/eidng8/go-attr-rbac/ent"
)

// AssignRoles assigns roles to a user.
//
// Endpoint: POST /users/{id}/roles
func (s Server) AssignRoles(
	_ context.Context, request AssignRolesRequestObject,
) (AssignRolesResponseObject, error) {
	_, err := s.db.Debug().Transaction(
		context.Background(),
		func(qc context.Context, tx *ent.Tx) (interface{}, error) {
			return nil, tx.User.UpdateOneID(request.Id).
				AddRoleIDs(*request.Body...).Exec(qc)
		},
	)
	if err != nil {
		// with soft delete, there's an extra select query to check if the user
		// was soft-deleted, so there will be an 404 error if the user was
		// soft-deleted or does not exist.
		if ent.IsNotFound(err) {
			return AssignRoles404JSONResponse{
				N404JSONResponse: N404JSONResponse{
					Code:   http.StatusNotFound,
					Errors: &msgNotFound,
					Status: msgError,
				},
			}, nil
		}
		if ent.IsForeignKeyError(err) {
			return AssignRoles400JSONResponse{
				N400JSONResponse: N400JSONResponse{
					Code:   http.StatusBadRequest,
					Errors: &msgInvalidAssignment,
					Status: msgError,
				},
			}, nil
		}
		return nil, err
	}
	return AssignRoles204Response{}, nil
}
