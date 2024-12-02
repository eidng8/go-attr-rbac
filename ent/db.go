package ent

import (
	"context"
	"log"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/eidng8/go-db"

	"github.com/eidng8/go-attr-rbac/ent/migrate"
)

func (c *Client) Setup() error {
	// Just make sure we have a basic empty db to work with.
	// Import data to db to fully use the API.
	// Or remove this auto-migration and use your own.
	return c.Schema.Create(
		context.Background(), migrate.WithDropIndex(true),
		migrate.WithDropColumn(true), migrate.WithForeignKeys(true),
	)
}

func Connect() (*Client, func()) {
	client := NewClient(Driver(entsql.OpenDB(db.ConnectX())))
	return client, func() {
		err := client.Close()
		if err != nil {
			log.Fatalf("Failed to close ent client: %s", err)
		}
	}
}
