package handlers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/eidng8/go-attr-rbac/ent"
)

// CreateRole creates a role.
//
// Endpoint: POST /roles
func (s Server) CreateRole(
	_ context.Context, request CreateRoleRequestObject,
) (CreateRoleResponseObject, error) {
	p, err := s.db.Transaction(
		context.Background(),
		func(qc context.Context, tx *ent.Tx) (interface{}, error) {
			create := tx.Role.Create().SetName(request.Body.Name)
			if request.Body.Description != nil {
				create.SetDescription(*request.Body.Description)
			}
			return create.Save(qc)
		},
	)
	if err != nil {
		if ent.IsUniqueKeyError(err) {
			var s interface{} = fmt.Sprintf(
				"role `%s` already exists", request.Body.Name,
			)
			return CreateRole400JSONResponse{
				N400JSONResponse: N400JSONResponse{
					Code:   http.StatusBadRequest,
					Errors: &s,
					Status: "error",
				},
			}, nil
		}
		return nil, err
	}
	perm := p.(*ent.Role)
	return CreateRole201JSONResponse{
		Id:          perm.ID,
		Name:        perm.Name,
		Description: &perm.Description,
		CreatedAt:   perm.CreatedAt,
	}, nil
}
