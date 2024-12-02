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

type User struct {
	ent.Schema
}

func (User) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.OnDelete(entsql.Restrict),
		edge.Annotation{StructTag: `json:"-"`},
	}
}

func (User) Fields() []ent.Field {
	u2 := uint64(2)
	u255 := uint64(255)
	return append(
		[]ent.Field{
			field.Uint64("id").Annotations(
				entoas.Schema(
					&ogen.Schema{
						Type:    "integer",
						Format:  "uint64",
						Minimum: ogen.Num("1"),
					},
				),
			),
			field.String("username").Unique().Annotations(
				entoas.Schema(
					&ogen.Schema{
						Type:      "string",
						MinLength: &u2,
						MaxLength: &u255,
					},
				),
			),
			field.String("email").Optional().Unique().Annotations(
				entoas.Schema(
					&ogen.Schema{
						Type:   "string",
						Format: "email",
					},
				),
			),
			field.String("password").Sensitive().NotEmpty().Annotations(
				entoas.Skip(true),
			),
		},
		ee.Timestamps()...,
	)
}

func (User) Edges() []ent.Edge {
	p := entoas.ListOperation(entoas.OperationPolicy(entoas.PolicyExclude))
	return []ent.Edge{
		edge.From("roles", Role.Type).Ref("users").Annotations(
			p, entsql.OnDelete(entsql.Restrict),
			entoas.ListOperation(entoas.OperationPolicy(entoas.PolicyExpose)),
		),
		edge.To("access_tokens", AccessToken.Type).Annotations(
			p, entsql.OnDelete(entsql.Restrict),
		),
		edge.To("refresh_tokens", AccessToken.Type).Annotations(
			p, entsql.OnDelete(entsql.Restrict),
		),
		edge.To("personal_tokens", PersonalToken.Type).Annotations(
			p, entsql.OnDelete(entsql.Restrict),
		),
	}
}

func (User) Mixin() []ent.Mixin {
	return []ent.Mixin{
		// Comment out these when running `go generate` for the first time
		softdelete.Mixin{},
	}
}

func (User) Interceptors() []ent.Interceptor {
	return []ent.Interceptor{
		// Comment out this when running `go generate` for the first time
		softdelete.Interceptor(intercept.NewQuery),
	}
}

func (User) Hooks() []ent.Hook {
	return []ent.Hook{
		// Comment out this when running `go generate` for the first time
		softdelete.Mutator[*gen.Client](),
	}
}
