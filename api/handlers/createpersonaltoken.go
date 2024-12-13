package handlers

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/eidng8/go-attr-rbac/api"
	"github.com/eidng8/go-attr-rbac/ent"
)

// CreatePersonalToken creates a personal token.
//
// Endpoint: POST /personal-tokens
func (s Server) CreatePersonalToken(
	ctx context.Context, request CreatePersonalTokenRequestObject,
) (CreatePersonalTokenResponseObject, error) {
	gc, ok := ctx.(*gin.Context)
	if !ok {
		return nil, errInvalidContext
	}
	at, err := s.getToken(gc)
	if err != nil {
		api.Log.Debugf("create personal token failed: %v", err)
		return CreatePersonalToken401JSONResponse{}, nil
	}
	uuid7, pt, err := s.issuePersonalToken(
		at.user, request.Body.Scopes,
		time.Second*time.Duration(request.Body.Ttl),
	)
	if err != nil {
		api.Log.Debugf("CreatePersonalToken error: %v", err)
		return nil, err
	}
	bin, err := uuid7.MarshalBinary()
	if err != nil {
		api.Log.Debugf("CreatePersonalToken error: %v", err)
		return nil, err
	}
	t, err := s.db.Transaction(
		context.Background(),
		func(qc context.Context, tx *ent.Tx) (interface{}, error) {
			return tx.PersonalToken.Create().SetUserID(at.user.ID).
				SetToken(bin).SetDescription(request.Body.Description).Save(qc)
		},
	)
	if err != nil {
		api.Log.Debugf("CreatePersonalToken error: %v", err)
		return nil, err
	}
	tt := t.(*ent.PersonalToken)
	return CreatePersonalToken201JSONResponse{
		Id:          tt.ID,
		Description: tt.Description,
		CreatedAt:   tt.CreatedAt,
		Token:       pt,
	}, nil
}
