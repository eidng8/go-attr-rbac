package api

import (
	"context"

	"github.com/eidng8/go-attr-rbac/ent/personaltoken"
)

// ReadPersonalToken verifies the specified personal token
func (s Server) ReadPersonalToken(
	ctx context.Context, request ReadPersonalTokenRequestObject,
) (ReadPersonalTokenResponseObject, error) {
	token, err := s.db.PersonalToken.Query().
		Where(personaltoken.ID(request.Id)).First(context.Background())
	if err != nil {
		return nil, err
	}
	return ReadPersonalToken200JSONResponse{
		Id:          token.ID,
		UserId:      token.UserID, // TODO remove this field
		Description: token.Description,
		CreatedAt:   token.CreatedAt,
	}, nil
}
