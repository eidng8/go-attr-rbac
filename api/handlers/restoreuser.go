package handlers

import (
	"context"
	"net/http"

	"github.com/eidng8/go-ent/softdelete"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/user"
)

// RestoreUser restores a user.
//
// Endpoint: POST /user/{id}/restore
func (s Server) RestoreUser(
	_ context.Context, request RestoreUserRequestObject,
) (RestoreUserResponseObject, error) {
	t := true
	_, err := s.db.Transaction(
		softdelete.NewSoftDeleteQueryContext(&t, context.Background()),
		func(qc context.Context, tx *ent.Tx) (interface{}, error) {
			return nil, tx.User.UpdateOneID(request.Id).
				Where(user.DeletedAtNotNil()).ClearDeletedAt().Exec(qc)
		},
	)
	if err != nil {
		if ent.IsNotFound(err) {
			return RestoreUser404JSONResponse{
				N404JSONResponse: N404JSONResponse{
					Code:   http.StatusNotFound,
					Status: msgError,
					Errors: &msgNotFound,
				},
			}, nil
		}
		return nil, err
	}
	return RestoreUser204Response{}, nil
}
