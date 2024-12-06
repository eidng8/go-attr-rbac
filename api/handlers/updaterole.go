package handlers

import (
	"context"

	"github.com/eidng8/go-attr-rbac/ent"
)

// UpdateRole updates a role.
//
// Endpoint: PATCH /role/{id}
func (s Server) UpdateRole(
	ctx context.Context, request UpdateRoleRequestObject,
) (UpdateRoleResponseObject, error) {
	r, err := s.db.Transaction(
		context.Background(),
		func(ctx context.Context, tx *ent.Tx) (interface{}, error) {
			r, err := tx.Role.UpdateOneID(request.Id).
				SetName(*request.Body.Name).
				SetDescription(*request.Body.Description).
				Save(ctx)
			if err != nil {
				return nil, err
			}
			return r, nil
		},
	)
	if err != nil {
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
