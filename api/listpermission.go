package api

import (
	"context"
	"net/http"

	"github.com/eidng8/go-ent/paginate"
	"github.com/gin-gonic/gin"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/permission"
)

type ListPermissionPaginateResponse struct {
	*paginate.PaginatedList[ent.Permission]
}

func (response ListPermissionPaginateResponse) VisitListPermissionResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	return json.NewEncoder(w).Encode(response)
}

// ListPermission lists permissions.
//
// Endpoint: GET /permissions
func (s Server) ListPermission(
	ctx context.Context, request ListPermissionRequestObject,
) (ListPermissionResponseObject, error) {
	gc, ok := ctx.(*gin.Context)
	if !ok {
		return nil, errInvalidContext
	}
	query := s.db.Permission.Query().Order(permission.ByID())
	if request.Params.Name != nil {
		query = query.Where(permission.NameHasPrefix(*request.Params.Name))
	}
	paginator := paginate.Paginator[ent.Permission, ent.PermissionQuery]{
		BaseUrl:  s.baseUrl,
		Query:    query,
		GinCtx:   gc,
		QueryCtx: context.Background(),
	}
	page, err := paginator.GetPage()
	if err != nil {
		Log.Debugf("ListPermission error: %v", err)
		return nil, err
	}
	return ListPermissionPaginateResponse{PaginatedList: page}, nil
}
