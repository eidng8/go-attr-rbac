package handlers

import (
	"context"

	"github.com/eidng8/go-attr-rbac/ent/role"
)

func (s Server) HintRoles(
	_ context.Context, request HintRolesRequestObject,
) (HintRolesResponseObject, error) {
	rows, err := s.db.Role.Query().Limit(s.hintSize).
		Select(role.FieldID, role.FieldName).
		Where(role.NameHasPrefix(request.Params.Q)).
		All(context.Background())
	if err != nil {
		return nil, err
	}
	list := make(HintRoles200JSONResponse, len(rows))
	for i, row := range rows {
		list[i] = RoleList{
			Id:   row.ID,
			Name: row.Name,
		}
	}
	return list, nil
}
