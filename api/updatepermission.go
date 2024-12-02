package api

import (
	"context"
	"fmt"

	"github.com/eidng8/go-attr-rbac/ent"
)

func (s Server) UpdatePermission(
	ctx context.Context, request UpdatePermissionRequestObject,
) (UpdatePermissionResponseObject, error) {
	p, err := s.db.Transaction(
		context.Background(),
		func(qc context.Context, tx *ent.Tx) (interface{}, error) {
			p, err := tx.Permission.UpdateOneID(request.Id).
				SetName(*request.Body.Name).
				SetDescription(*request.Body.Description).Save(ctx)
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
		return nil, fmt.Errorf("invalid permission type: %t", p)
	}
	return UpdatePermission200JSONResponse{
		Id:          perm.ID,
		Name:        perm.Name,
		Description: &perm.Description,
		CreatedAt:   perm.CreatedAt,
		UpdatedAt:   perm.UpdatedAt,
	}, nil
}
