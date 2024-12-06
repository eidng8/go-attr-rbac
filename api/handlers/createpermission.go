package handlers

import (
	"context"
	"fmt"

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
			p, err := tx.Permission.Create().
				SetName(request.Body.Name).
				SetDescription(*request.Body.Description).
				Save(ctx)
			if err != nil {
				return nil, err
			}
			return p, nil
		},
	)
	if err != nil {
		return nil, err
	}
	perm, ok := p.(*ent.Permission)
	if !ok {
		return nil, fmt.Errorf("failed to create permission: %T", p)
	}
	return CreatePermission200JSONResponse{
		Id:          perm.ID,
		Name:        perm.Name,
		Description: &perm.Description,
		CreatedAt:   perm.CreatedAt,
	}, nil
}
