package api

import (
    "context"
    "fmt"

    "github.com/gin-gonic/gin"
)

func (s Server) CheckAccessToken(
    ctx context.Context, _ CheckAccessTokenRequestObject,
) (CheckAccessTokenResponseObject, error) {
    gc, ok := ctx.(*gin.Context)
    if !ok {
        return nil, fmt.Errorf("invalid context type %T", ctx)
    }
    if _, err := s.verifyAccessToken(gc); err != nil {
        return CheckAccessToken401Response{}, nil
    }
    return CheckAccessToken204Response{}, nil
}
