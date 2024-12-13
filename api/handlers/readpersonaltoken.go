package handlers

import (
	"context"

	"github.com/eidng8/go-attr-rbac/api"
	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/personaltoken"
)

// ReadPersonalToken verifies the specified personal token and returns its user.
//
// Endpoint: GET "/personal-token/{id}"
func (s Server) ReadPersonalToken(
	ctx context.Context, request ReadPersonalTokenRequestObject,
) (ReadPersonalTokenResponseObject, error) {
	token, err := s.db.PersonalToken.Query().
		Where(personaltoken.ID(request.Id)).First(context.Background())
	if err != nil {
		if ent.IsNotFound(err) {
			return ReadPersonalToken404JSONResponse{}, nil
		}
		api.Log.Debugf("ReadPersonalToken error: %v", err)
		return nil, err
	}
	return ReadPersonalToken200JSONResponse{
		Id:          token.ID,
		UserId:      token.UserID, // TODO remove this field
		Description: token.Description,
		CreatedAt:   token.CreatedAt,
	}, nil
}
