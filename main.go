package main

import (
	"context"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/eidng8/go-db"
	"github.com/eidng8/go-utils"

	"github.com/eidng8/go-attr-rbac/api"
	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/migrate"
)

func main() {
	ec := ent.NewClient(ent.Driver(entsql.OpenDB(db.ConnectX())))
	defer api.Log.PanicIfError(ec.Close())
	api.Log.PanicIfError(DbSetup(ec))
	_, engine, err := api.NewEngine(ec)
	api.Log.PanicIfError(err)
	api.Log.PanicIfError(engine.Run(utils.GetEnvWithDefault("LISTEN", ":80")))
}

func DbSetup(c *ent.Client) error {
	// Just make sure we have a basic empty db to work with.
	// Import data to db to fully use the API.
	// Or remove this auto-migration and use your own.
	return c.Schema.Create(
		context.Background(), migrate.WithDropIndex(true),
		migrate.WithDropColumn(true), migrate.WithForeignKeys(true),
	)
}
