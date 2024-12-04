package api

import "context"

func (s Server) Ping(
	_ context.Context, _ PingRequestObject,
) (PingResponseObject, error) {
	return Ping204Response{}, nil
}
