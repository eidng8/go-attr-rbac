package handlers

import (
	"context"
	"net/http"

	"github.com/eidng8/go-ent/paginate"
	"github.com/gin-gonic/gin"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/permission"
	"github.com/eidng8/go-attr-rbac/ent/role"
)

type ListRolePermissionsPaginateResponse struct {
	*paginate.PaginatedList[ent.Permission]
}

func (response ListRolePermissionsPaginateResponse) VisitListRolePermissionsResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	return json.NewEncoder(w).Encode(response)
}

func (s Server) ListRolePermissions(
	ctx context.Context, request ListRolePermissionsRequestObject,
) (ListRolePermissionsResponseObject, error) {
	gc, ok := ctx.(*gin.Context)
	if !ok {
		return nil, errInvalidContext
	}
	query := s.db.Role.Query().Where(role.IDEQ(request.Id)).QueryPermissions().
		Order(permission.ByID())
	paginator := paginate.Paginator[ent.Permission, ent.PermissionQuery]{
		BaseUrl:  s.baseUrl,
		Query:    query,
		GinCtx:   gc,
		QueryCtx: context.Background(),
	}
	page, err := paginator.GetPage()
	if err != nil {
		return nil, err
	}
	return ListRolePermissionsPaginateResponse{PaginatedList: page}, nil
}
