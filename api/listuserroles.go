package api

import (
	"context"
	"net/http"

	"github.com/eidng8/go-ent/paginate"
	"github.com/gin-gonic/gin"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/role"
	"github.com/eidng8/go-attr-rbac/ent/user"
)

type ListUserRolesPaginateResponse struct {
	*paginate.PaginatedList[ent.Role]
}

func (response ListUserRolesPaginateResponse) VisitListUserRolesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	return json.NewEncoder(w).Encode(response)
}

func (s Server) ListUserRoles(
	ctx context.Context, request ListUserRolesRequestObject,
) (ListUserRolesResponseObject, error) {
	gc, ok := ctx.(*gin.Context)
	if !ok {
		return nil, ErrInvalidContext
	}
	query := s.db.User.Query().Where(user.IDEQ(request.Id)).QueryRoles().
		Order(role.ByID())
	paginator := paginate.Paginator[ent.Role, ent.RoleQuery]{
		BaseUrl:  s.baseUrl,
		Query:    query,
		GinCtx:   gc,
		QueryCtx: context.Background(),
	}
	page, err := paginator.GetPage()
	if err != nil {
		return nil, err
	}
	return ListUserRolesPaginateResponse{PaginatedList: page}, nil
}
