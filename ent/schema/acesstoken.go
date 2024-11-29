package schema

import (
	"time"

	"entgo.io/contrib/entoas"
	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/ogen-go/ogen"
)

// AccessToken holds the schema definition for the AccessToken entity.
// This table stores revoked access tokens (black list), and shall be cleaned up
// periodically to remove expired tokens.
type AccessToken struct {
	ent.Schema
}

func (AccessToken) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.OnDelete(entsql.Restrict),
		edge.Annotation{StructTag: `json:"-"`},
	}
}

func (AccessToken) Annotations() []schema.Annotation {
	return []schema.Annotation{
		schema.Comment("Stores revoked access tokens"),
	}
}

func (AccessToken) Fields() []ent.Field {
	return []ent.Field{
		field.Uint64("id").Annotations(
			entoas.Schema(
				&ogen.Schema{
					Type:    "integer",
					Format:  "uint64",
					Minimum: ogen.Num("1"),
				},
			),
		),
		field.Uint64("user_id").Annotations(
			entoas.Schema(
				&ogen.Schema{
					Type:    "integer",
					Format:  "uint64",
					Minimum: ogen.Num("1"),
				},
			),
		),
		field.Bytes("access_token").Sensitive().Unique().SchemaType(
			map[string]string{
				dialect.MySQL:    "binary(32)",
				dialect.Postgres: "binary(32)",
			},
		).Annotations(entoas.Skip(true)),
		field.Bytes("refresh_token").Sensitive().Unique().SchemaType(
			map[string]string{
				dialect.MySQL:    "binary(32)",
				dialect.Postgres: "binary(32)",
			},
		).Annotations(entoas.Skip(true)),
		field.Time("created_at").Optional().Nillable().Immutable().
			Default(time.Now).Annotations(
			entoas.Schema(
				&ogen.Schema{
					Type:   "string",
					Format: "date-time",
				},
			),
		),
	}
}

func (AccessToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", User.Type).Ref("access_tokens").Unique().
			Annotations(
				entoas.ReadOperation(
					entoas.OperationPolicy(entoas.PolicyExclude),
				),
			),
	}
}
