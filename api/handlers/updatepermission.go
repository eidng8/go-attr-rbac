package handlers

import (
	"context"
	"net/http"

	"github.com/eidng8/go-attr-rbac/api"
	"github.com/eidng8/go-attr-rbac/ent"
)

// UpdatePermission updates a permission.
//
// Endpoint: PATCH /permission/{id}
func (s Server) UpdatePermission(
	ctx context.Context, request UpdatePermissionRequestObject,
) (UpdatePermissionResponseObject, error) {
	if nil == request.Body.Name && nil == request.Body.Description &&
		(nil == request.Body.Roles || len(*request.Body.Roles) == 0) {
		return UpdatePermission422JSONResponse{
			N422JSONResponse: N422JSONResponse{
				Code:   http.StatusUnprocessableEntity,
				Status: msgError,
				Errors: &msgEmptyRequest,
			},
		}, nil
	}
	p, err := s.db.Transaction(
		context.Background(),
		func(qc context.Context, tx *ent.Tx) (interface{}, error) {
			p := tx.Permission.UpdateOneID(request.Id)
			if request.Body.Name != nil {
				p.SetName(*request.Body.Name)
			}
			if request.Body.Description != nil {
				p.SetDescription(*request.Body.Description)
			}
			if request.Body.Roles != nil && len(*request.Body.Roles) > 0 {
				p.ClearRoles()
				p.AddRoleIDs(*request.Body.Roles...)
			}
			return p.Save(ctx)
		},
	)
	if err != nil {
		if ent.IsNotFound(err) {
			return UpdatePermission404JSONResponse{
				N404JSONResponse: N404JSONResponse{
					Code:   http.StatusNotFound,
					Status: msgError,
					Errors: &msgNotFound,
				},
			}, nil
		}
		api.Log.Debugf("UpdatePermission error: %v", err)
		return nil, err
	}
	perm := p.(*ent.Permission)
	return UpdatePermission200JSONResponse{
		Id:          perm.ID,
		Name:        perm.Name,
		Description: &perm.Description,
		CreatedAt:   perm.CreatedAt,
		UpdatedAt:   perm.UpdatedAt,
	}, nil
}
