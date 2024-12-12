package handlers

import (
	"context"
	"net/http"

	"github.com/eidng8/go-attr-rbac/ent"
)

// UpdateRole updates a role.
//
// Endpoint: PATCH /role/{id}
func (s Server) UpdateRole(
	_ context.Context, request UpdateRoleRequestObject,
) (UpdateRoleResponseObject, error) {
	if nil == request.Body.Name && nil == request.Body.Description &&
		(nil == request.Body.Permissions || len(*request.Body.Permissions) == 0) &&
		(nil == request.Body.Users || len(*request.Body.Users) == 0) {
		var s interface{} = "empty request"
		return UpdateRole422JSONResponse{
			N422JSONResponse: N422JSONResponse{
				Code:   http.StatusUnprocessableEntity,
				Status: "error",
				Errors: &s,
			},
		}, nil
	}
	r, err := s.db.Transaction(
		context.Background(),
		func(qc context.Context, tx *ent.Tx) (interface{}, error) {
			r := tx.Role.UpdateOneID(request.Id)
			if request.Body.Name != nil {
				r.SetName(*request.Body.Name)
			}
			if request.Body.Description != nil {
				r.SetDescription(*request.Body.Description)
			}
			if request.Body.Permissions != nil && len(*request.Body.Permissions) > 0 {
				r.ClearPermissions()
				r.AddPermissionIDs(*request.Body.Permissions...)
			}
			if request.Body.Users != nil && len(*request.Body.Users) > 0 {
				r.ClearUsers()
				r.AddUserIDs(*request.Body.Users...)
			}
			return r.Save(qc)
		},
	)
	if err != nil {
		if ent.IsNotFound(err) {
			var s interface{} = "not found"
			return UpdateRole404JSONResponse{
				N404JSONResponse: N404JSONResponse{
					Code:   http.StatusNotFound,
					Status: "error",
					Errors: &s,
				},
			}, nil
		}
		return nil, err
	}
	ro := r.(*ent.Role)
	return UpdateRole200JSONResponse{
		Id:          ro.ID,
		Name:        ro.Name,
		Description: &ro.Description,
		CreatedAt:   ro.CreatedAt,
		UpdatedAt:   ro.UpdatedAt,
	}, nil
}
