package handlers

import (
	"context"
	"net/http"

	"github.com/eidng8/go-ent/paginate"
	"github.com/gin-gonic/gin"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/user"
)

type ListUserPaginateResponse struct {
	*paginate.PaginatedList[ent.User]
}

func (response ListUserPaginateResponse) VisitListUserResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	return json.NewEncoder(w).Encode(response)
}

// ListUser lists users.
//
// Endpoint: GET /users
func (s Server) ListUser(
	ctx context.Context, request ListUserRequestObject,
) (ListUserResponseObject, error) {
	gc, ok := ctx.(*gin.Context)
	if !ok {
		return nil, errInvalidContext
	}
	query := s.db.User.Query().Order(user.ByID())
	if request.Params.Name != nil {
		query = query.Where(
			user.Or(
				user.UsernameHasPrefix(*request.Params.Name),
				user.EmailHasPrefix(*request.Params.Name),
			),
		)
	}
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
	return ListUserPaginateResponse{PaginatedList: page}, nil
}
