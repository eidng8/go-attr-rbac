package api

import (
	"context"
	"net/http"

	"github.com/eidng8/go-attr-rbac/ent"
)

// DeleteRole deletes a role.
//
// Endpoint: DELETE /role/{id}
func (s Server) DeleteRole(
	_ context.Context, request DeleteRoleRequestObject,
) (DeleteRoleResponseObject, error) {
	_, err := s.db.Transaction(
		context.Background(),
		func(qc context.Context, tx *ent.Tx) (interface{}, error) {
			return nil, tx.Role.DeleteOneID(request.Id).Exec(qc)
		},
	)
	if err != nil {
		if ent.IsNotFound(err) {
			return DeleteRole404JSONResponse{
				N404JSONResponse: N404JSONResponse{
					Code:   http.StatusNotFound,
					Status: msgError,
					Errors: &msgNotFound,
				},
			}, nil
		}
		Log.Debugf("DeleteRole error: %v", err)
		return nil, err
	}
	return DeleteRole204Response{}, nil
}
