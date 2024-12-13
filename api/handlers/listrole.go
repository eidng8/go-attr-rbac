package handlers

import (
	"context"
	"net/http"

	"github.com/eidng8/go-ent/paginate"
	"github.com/gin-gonic/gin"

	"github.com/eidng8/go-attr-rbac/api"
	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/role"
)

type ListRolePaginateResponse struct {
	*paginate.PaginatedList[ent.Role]
}

func (response ListRolePaginateResponse) VisitListRoleResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	return json.NewEncoder(w).Encode(response)
}

// ListRole lists roles.
//
// Endpoint: GET /roles
func (s Server) ListRole(
	ctx context.Context, request ListRoleRequestObject,
) (ListRoleResponseObject, error) {
	gc, ok := ctx.(*gin.Context)
	if !ok {
		return nil, errInvalidContext
	}
	query := s.db.Role.Query().Order(role.ByID())
	if request.Params.Name != nil {
		query = query.Where(role.NameHasPrefix(*request.Params.Name))
	}
	paginator := paginate.Paginator[ent.Role, ent.RoleQuery]{
		BaseUrl:  s.baseUrl,
		Query:    query,
		GinCtx:   gc,
		QueryCtx: context.Background(),
	}
	page, err := paginator.GetPage()
	if err != nil {
		api.Log.Debugf("ListRole error: %v", err)
		return nil, err
	}
	return ListRolePaginateResponse{PaginatedList: page}, nil
}
