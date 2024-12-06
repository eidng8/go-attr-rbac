package handlers

import (
	"context"
	"net/http"

	"github.com/eidng8/go-ent/paginate"
	"github.com/gin-gonic/gin"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/personaltoken"
)

type ListPersonalTokenPaginateResponse struct {
	*paginate.PaginatedList[ent.PersonalToken]
}

func (response ListPersonalTokenPaginateResponse) VisitListPersonalTokenResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	return json.NewEncoder(w).Encode(response)
}

// ListPersonalToken lists personal tokens.
//
// Endpoint: GET "/personal-tokens"
func (s Server) ListPersonalToken(
	ctx context.Context, _ ListPersonalTokenRequestObject,
) (ListPersonalTokenResponseObject, error) {
	gc, ok := ctx.(*gin.Context)
	if !ok {
		return nil, errInvalidContext
	}
	query := s.db.PersonalToken.Query().Order(personaltoken.ByID())
	paginator := paginate.Paginator[ent.PersonalToken, ent.PersonalTokenQuery]{
		BaseUrl:  s.baseUrl,
		Query:    query,
		GinCtx:   gc,
		QueryCtx: context.Background(),
	}
	page, err := paginator.GetPage()
	if err != nil {
		return nil, err
	}
	return ListPersonalTokenPaginateResponse{PaginatedList: page}, nil
}
