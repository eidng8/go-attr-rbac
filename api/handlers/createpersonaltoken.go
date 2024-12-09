package handlers

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/eidng8/go-attr-rbac/ent"
)

type ut struct {
	token *ent.PersonalToken
	user  *ent.User
}

// CreatePersonalToken creates a personal token.
//
// Endpoint: POST /personal-tokens
func (s Server) CreatePersonalToken(
	ctx context.Context, request CreatePersonalTokenRequestObject,
) (CreatePersonalTokenResponseObject, error) {
	t, err := s.db.Transaction(
		context.Background(),
		func(ctx context.Context, tx *ent.Tx) (interface{}, error) {
			gc, ok := ctx.(*gin.Context)
			if !ok {
				return nil, errInvalidContext
			}
			token := gc.Value(accessTokenName).(*jwtToken)
			t, err := tx.PersonalToken.Create().
				SetDescription(request.Body.Description).Save(ctx)
			if err != nil {
				return nil, err
			}
			return ut{
				token: t,
				user:  token.user,
			}, nil
		},
	)
	if err != nil {
		return nil, err
	}
	tt := t.(ut)
	// TODO change to return JWT token string
	return CreatePersonalToken201JSONResponse{
		Id:          tt.token.ID,
		UserId:      tt.token.UserID,
		Description: tt.token.Description,
		CreatedAt:   tt.token.CreatedAt,
	}, nil
}
