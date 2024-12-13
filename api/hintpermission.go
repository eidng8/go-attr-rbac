package api

import (
	"context"

	"github.com/eidng8/go-attr-rbac/ent/permission"
)

// HintPermissions returns a short list of permissions.
//
// Endpoint: GET /q/permissions
func (s Server) HintPermissions(
	_ context.Context, request HintPermissionsRequestObject,
) (HintPermissionsResponseObject, error) {
	rows, err := s.db.Permission.Query().Limit(s.hintSize).
		Select(permission.FieldID, permission.FieldName).
		Where(permission.NameHasPrefix(request.Params.Q)).
		All(context.Background())
	if err != nil {
		Log.Debugf("HintPermissions error: %v", err)
		return nil, err
	}
	list := make(HintPermissions200JSONResponse, len(rows))
	for i, row := range rows {
		list[i] = PermissionList{
			Id:   row.ID,
			Name: row.Name,
		}
	}
	return list, nil
}
