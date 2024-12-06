package handlers

import "context"

// Ping checks whether the server is alive.
//
// Endpoint: GET /ping
func (s Server) Ping(
	_ context.Context, _ PingRequestObject,
) (PingResponseObject, error) {
	return Ping204Response{}, nil
}
