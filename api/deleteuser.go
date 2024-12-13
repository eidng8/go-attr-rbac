package api

import (
	"context"
	"net/http"

	"github.com/eidng8/go-ent/softdelete"

	"github.com/eidng8/go-attr-rbac/ent"
)

// DeleteUser deletes a user.
//
// Endpoint: DELETE /user/{id}
func (s Server) DeleteUser(
	_ context.Context, request DeleteUserRequestObject,
) (DeleteUserResponseObject, error) {
	_, err := s.db.Transaction(
		softdelete.NewSoftDeleteQueryContext(
			request.Params.Trashed, context.Background(),
		),
		func(qc context.Context, tx *ent.Tx) (interface{}, error) {
			return nil, tx.User.DeleteOneID(request.Id).Exec(qc)
		},
	)
	if err != nil {
		if ent.IsNotFound(err) {
			return DeleteUser404JSONResponse{
				N404JSONResponse: N404JSONResponse{
					Code:   http.StatusNotFound,
					Status: msgError,
					Errors: &msgNotFound,
				},
			}, nil
		}
		Log.Debugf("DeleteUser error: %v", err)
		return nil, err
	}
	return DeleteUser204Response{}, nil
}
