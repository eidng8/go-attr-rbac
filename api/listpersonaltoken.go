package api

import (
    "context"
    "fmt"

    "github.com/eidng8/go-ent/paginate"
    "github.com/gin-gonic/gin"

    "github.com/eidng8/go-attr-rbac/ent"
    "github.com/eidng8/go-attr-rbac/ent/personaltoken"
)

func (s Server) ListPersonalToken(
    ctx context.Context, _ ListPersonalTokenRequestObject,
) (ListPersonalTokenResponseObject, error) {
    gc, ok := ctx.(*gin.Context)
    if !ok {
        return nil, fmt.Errorf("invalid context type %T", ctx)
    }
    if _, err := s.verifyAccessToken(gc); err != nil {
        return ListPersonalToken401Response{}, nil
    }
    query := s.db.PersonalToken.Query().Order(personaltoken.ByID())
    paginator := paginate.Paginator[ent.PersonalToken, ent.PersonalTokenQuery, *ent.PersonalTokenQuery]{
        BaseUrl:  s.baseUrl,
        Query:    query,
        GinCtx:   gc,
        QueryCtx: context.Background(),
    }
    page, err := paginator.GetPage()
    if err != nil {
        return nil, err
    }

    tokens := make([]PersonalTokenList, len(page.Data))
    for i, t := range page.Data {
        tokens[i] = PersonalTokenList{
            Id:          t.ID,
            UserId:      t.UserID,
            Description: t.Description,
            CreatedAt:   t.CreatedAt,
        }
    }
    return ListPersonalToken200JSONResponse{
        CurrentPage:  page.CurrentPage,
        FirstPageUrl: page.FirstPageUrl,
        From:         page.From,
        LastPage:     page.LastPage,
        LastPageUrl:  page.LastPageUrl,
        NextPageUrl:  page.NextPageUrl,
        Path:         page.Path,
        PerPage:      page.PerPage,
        PrevPageUrl:  page.PrevPageUrl,
        To:           page.To,
        Total:        page.Total,
        Data:         tokens,
    }, nil
}
