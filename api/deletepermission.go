package api

import (
	"context"
	"net/http"

	"github.com/eidng8/go-attr-rbac/ent"
)

// DeletePermission deletes a permission.
//
// Endpoint: DELETE /permission/{id}
func (s Server) DeletePermission(
	ctx context.Context, request DeletePermissionRequestObject,
) (DeletePermissionResponseObject, error) {
	_, err := s.db.Transaction(
		context.Background(),
		func(qc context.Context, tx *ent.Tx) (interface{}, error) {
			return nil, tx.Permission.DeleteOneID(request.Id).Exec(ctx)
		},
	)
	if err != nil {
		if ent.IsNotFound(err) {
			return DeletePermission404JSONResponse{
				N404JSONResponse: N404JSONResponse{
					Code:   http.StatusNotFound,
					Status: msgError,
					Errors: &msgNotFound,
				},
			}, nil
		}
		Log.Debugf("DeletePermission error: %v", err)
		return nil, err
	}
	return DeletePermission204Response{}, nil
}
