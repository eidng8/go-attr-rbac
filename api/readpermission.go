package api

import (
	"context"

	"github.com/eidng8/go-attr-rbac/ent/permission"
)

func (s Server) ReadPermission(
	ctx context.Context, request ReadPermissionRequestObject,
) (ReadPermissionResponseObject, error) {
	p, err := s.db.Permission.Query().Where(permission.ID(request.Id)).Only(ctx)
	if err != nil {
		return nil, err
	}
	return ReadPermission200JSONResponse{
		Id:          p.ID,
		Name:        p.Name,
		Description: &p.Description,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}, nil
}
