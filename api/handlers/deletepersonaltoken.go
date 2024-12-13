package handlers

import (
	"context"
	"net/http"

	"github.com/eidng8/go-attr-rbac/ent"
)

// DeletePersonalToken revokes a personal token.
//
// Endpoint: DELETE /personal-token/:id
func (s Server) DeletePersonalToken(
	_ context.Context, request DeletePersonalTokenRequestObject,
) (DeletePersonalTokenResponseObject, error) {
	_, err := s.db.Transaction(
		context.Background(),
		func(qc context.Context, tx *ent.Tx) (interface{}, error) {
			return nil, tx.PersonalToken.DeleteOneID(request.Id).Exec(qc)
		},
	)
	if err != nil {
		if ent.IsNotFound(err) {
			return DeletePersonalToken404JSONResponse{
				N404JSONResponse: N404JSONResponse{
					Code:   http.StatusNotFound,
					Status: msgError,
					Errors: &msgNotFound,
				},
			}, nil
		}
		return nil, err
	}
	return DeletePersonalToken204Response{}, nil
}
