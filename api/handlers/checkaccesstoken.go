package handlers

import (
	"context"
)

func (s Server) CheckAccessToken(
	ctx context.Context, _ CheckAccessTokenRequestObject,
) (CheckAccessTokenResponseObject, error) {
	return CheckAccessToken204Response{}, nil
}
