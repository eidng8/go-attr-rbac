package api

import (
	"context"
	"net/http"

	"github.com/eidng8/go-attr-rbac/ent"
)

// CreatePermission creates a permission.
//
// Endpoint: POST /permissions
func (s Server) CreatePermission(
	_ context.Context, request CreatePermissionRequestObject,
) (CreatePermissionResponseObject, error) {
	p, err := s.db.Transaction(
		context.Background(),
		func(qc context.Context, tx *ent.Tx) (interface{}, error) {
			create := tx.Permission.Create().SetName(request.Body.Name)
			if request.Body.Description != nil {
				create.SetDescription(*request.Body.Description)
			}
			return create.Save(qc)
		},
	)
	if err != nil {
		if ent.IsUniqueKeyError(err) {
			return CreatePermission400JSONResponse{
				N400JSONResponse: N400JSONResponse{
					Code:   http.StatusBadRequest,
					Errors: &msgExists,
					Status: msgError,
				},
			}, nil
		}
		return nil, err
	}
	perm := p.(*ent.Permission)
	return CreatePermission201JSONResponse{
		Id:          perm.ID,
		Name:        perm.Name,
		Description: &perm.Description,
		CreatedAt:   perm.CreatedAt,
	}, nil
}
