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

// PersonalToken holds the schema definition for the PersonalToken entity.
// This table stores issued access tokens (white list).
type PersonalToken struct {
	ent.Schema
}

func (PersonalToken) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.OnDelete(entsql.Restrict),
		entsql.WithComments(true),
		schema.Comment("Stores issued long-lived access tokens"),
		edge.Annotation{StructTag: `json:"-"`},
	}
}

func (PersonalToken) Fields() []ent.Field {
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
		field.String("description").Annotations(
			entoas.Schema(
				&ogen.Schema{
					Type:    "string",
					Format:  "uint64",
					Minimum: ogen.Num("1"),
					Maximum: ogen.Num("255"),
				},
			),
		),
		field.Bytes("token").Sensitive().Unique().
			SchemaType(
				map[string]string{
					dialect.MySQL:    "binary(32)",
					dialect.Postgres: "binary(32)",
				},
			).
			Annotations(entoas.Skip(true)),
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

func (PersonalToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", User.Type).Ref("personal_tokens").Unique().
			Annotations(
				entoas.ReadOperation(
					entoas.OperationPolicy(entoas.PolicyExclude),
				),
			),
	}
}
