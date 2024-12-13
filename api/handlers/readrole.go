package handlers

import (
	"context"

	"github.com/eidng8/go-attr-rbac/api"
	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/role"
)

// ReadRole reads a role.
//
// Endpoint: GET /role/{id}
func (s Server) ReadRole(
	ctx context.Context, request ReadRoleRequestObject,
) (ReadRoleResponseObject, error) {
	r, err := s.db.Role.Query().Where(role.ID(request.Id)).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ReadRole404JSONResponse{}, nil
		}
		api.Log.Debugf("ReadRole error: %v", err)
		return nil, err
	}
	return ReadRole200JSONResponse{
		Id:          r.ID,
		Name:        r.Name,
		Description: &r.Description,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}, nil
}
