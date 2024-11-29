package main

import (
	"log"

	"github.com/eidng8/go-utils"
	jsoniter "github.com/json-iterator/go"

	"github.com/eidng8/go-attr-rbac/api"
	"github.com/eidng8/go-attr-rbac/ent"
	_ "github.com/eidng8/go-attr-rbac/ent/runtime"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

func main() {
	db, cleanup := ent.Connect()
	defer cleanup()
	if err := db.Setup(); err != nil {
		log.Fatalf("Failed to setup server: %s", err)
	}
	_, engine, err := api.NewEngine(db)
	if err != nil {
		log.Fatalf("Failed to create server: %s", err)
	}
	if err = engine.Run(utils.GetEnvWithDefault("LISTEN", ":80")); err != nil {
		log.Fatalf("Server exits due to fatal error: %s", err)
	}
}
