package main

//go:generate go run -mod=mod -modfile=./tools/go.mod ./tools/entc.go
//go:generate go run -mod=mod github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen --config=./tools/oapi-types.json ./ent/openapi.json
//go:generate go run -mod=mod github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen --config=./tools/oapi-services.json ./ent/openapi.json
