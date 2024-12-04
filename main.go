package main

import (
	entsql "entgo.io/ent/dialect/sql"
	"github.com/eidng8/go-db"
	"github.com/eidng8/go-utils"

	"github.com/eidng8/go-attr-rbac/api"
	"github.com/eidng8/go-attr-rbac/ent"
)

func main() {
	ec := ent.NewClient(ent.Driver(entsql.OpenDB(db.ConnectX())))
	defer api.Log.PanicIfError(ec.Close())
	_, engine, err := api.NewEngine(ec)
	api.Log.PanicIfError(err)
	api.Log.PanicIfError(engine.Run(utils.GetEnvWithDefault("LISTEN", ":80")))
}
