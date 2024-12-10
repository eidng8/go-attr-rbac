package handlers

import (
	"context"
	"fmt"

	"github.com/eidng8/go-attr-rbac/ent"
)

// CreateRole creates a role.
//
// Endpoint: POST /roles
func (s Server) CreateRole(
	ctx context.Context, request CreateRoleRequestObject,
) (CreateRoleResponseObject, error) {
	p, err := s.db.Transaction(
		context.Background(),
		func(qc context.Context, tx *ent.Tx) (interface{}, error) {
			p, err := tx.Role.Create().
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
	perm, ok := p.(*ent.Role)
	if !ok {
		return nil, fmt.Errorf("failed to create role: %T", p)
	}
	return CreateRole201JSONResponse{
		Id:          perm.ID,
		Name:        perm.Name,
		Description: &perm.Description,
		CreatedAt:   perm.CreatedAt,
	}, nil
}
