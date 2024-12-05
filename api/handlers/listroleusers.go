package handlers

import (
	"context"
	"net/http"

	"github.com/eidng8/go-ent/paginate"
	"github.com/gin-gonic/gin"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/role"
	"github.com/eidng8/go-attr-rbac/ent/user"
)

type ListRoleUsersPaginateResponse struct {
	*paginate.PaginatedList[ent.User]
}

func (response ListRoleUsersPaginateResponse) VisitListRoleUsersResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	return json.NewEncoder(w).Encode(response)
}

func (s Server) ListRoleUsers(
	ctx context.Context, request ListRoleUsersRequestObject,
) (ListRoleUsersResponseObject, error) {
	gc, ok := ctx.(*gin.Context)
	if !ok {
		return nil, errInvalidContext
	}
	query := s.db.Role.Query().Where(role.IDEQ(request.Id)).QueryUsers().
		Order(user.ByID())
	paginator := paginate.Paginator[ent.User, ent.UserQuery]{
		BaseUrl:  s.baseUrl,
		Query:    query,
		GinCtx:   gc,
		QueryCtx: context.Background(),
	}
	page, err := paginator.GetPage()
	if err != nil {
		return nil, err
	}
	return ListRoleUsersPaginateResponse{PaginatedList: page}, nil
}
