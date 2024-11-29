package schema

import (
	"entgo.io/contrib/entoas"
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	ee "github.com/eidng8/go-ent"
	"github.com/eidng8/go-ent/softdelete"
	"github.com/ogen-go/ogen"

	gen "github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/intercept"
)

type Role struct {
	ent.Schema
}

func (Role) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.OnDelete(entsql.Restrict),
		edge.Annotation{StructTag: `json:"-"`},
	}
}

func (Role) Fields() []ent.Field {
	return append(
		[]ent.Field{
			field.Uint32("id").Annotations(
				entoas.Schema(
					&ogen.Schema{
						Type:    "integer",
						Format:  "uint32",
						Minimum: ogen.Num("1"),
					},
				),
			),
			field.String("name").Unique(),
			field.String("description").Optional(),
		},
		ee.Timestamps()...,
	)
}

func (Role) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("permissions", Permission.Type).Annotations(),
		edge.To("users", User.Type).Annotations(),
	}
}

func (Role) Mixin() []ent.Mixin {
	return []ent.Mixin{
		// Comment out these when running `go generate` for the first time
		softdelete.Mixin{},
	}
}

func (Role) Interceptors() []ent.Interceptor {
	return []ent.Interceptor{
		// Comment out this when running `go generate` for the first time
		softdelete.Interceptor(intercept.NewQuery),
	}
}

func (Role) Hooks() []ent.Hook {
	return []ent.Hook{
		// Comment out this when running `go generate` for the first time
		softdelete.Mutator[*gen.Client](),
	}
}
