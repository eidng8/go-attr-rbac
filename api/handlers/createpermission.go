package handlers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/eidng8/go-attr-rbac/ent"
)

// CreatePermission creates a permission.
//
// Endpoint: POST /permissions
func (s Server) CreatePermission(
	ctx context.Context, request CreatePermissionRequestObject,
) (CreatePermissionResponseObject, error) {
	p, err := s.db.Transaction(
		context.Background(),
		func(qc context.Context, tx *ent.Tx) (interface{}, error) {
			create := tx.Permission.Create().SetName(request.Body.Name)
			if request.Body.Description != nil {
				create.SetDescription(*request.Body.Description)
			}
			return create.Save(ctx)
		},
	)
	if err != nil {
		if ent.IsUniqueKeyError(err) {
			var s interface{} = fmt.Sprintf(
				"permission `%s` already exists", request.Body.Name,
			)
			return CreatePermission400JSONResponse{
				N400JSONResponse: N400JSONResponse{
					Code:   http.StatusBadRequest,
					Errors: &s,
					Status: "error",
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
