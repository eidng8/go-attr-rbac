package schema

import (
	"entgo.io/contrib/entoas"
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	ee "github.com/eidng8/go-ent"
	"github.com/ogen-go/ogen"
)

type Permission struct {
	ent.Schema
}

func (Permission) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.OnDelete(entsql.Restrict),
		edge.Annotation{StructTag: `json:"-"`},
	}
}

func (Permission) Fields() []ent.Field {
	u1 := uint64(1)
	u255 := uint64(255)
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
			field.String("name").Unique().NotEmpty().Annotations(
				entoas.Schema(
					&ogen.Schema{
						Type:      "string",
						MinLength: &u1,
						MaxLength: &u255,
					},
				),
			),
			field.String("description").Optional().Annotations(
				entoas.Schema(
					&ogen.Schema{
						Type:      "string",
						MaxLength: &u255,
					},
				),
			),
		},
		ee.Timestamps()...,
	)
}

func (Permission) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("roles", Role.Type).Ref("permissions").Annotations(
			entsql.OnDelete(entsql.Restrict),
			entoas.ListOperation(entoas.OperationPolicy(entoas.PolicyExclude)),
		),
	}
}
