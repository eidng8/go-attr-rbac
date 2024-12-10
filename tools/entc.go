//go:build ignore
// +build ignore

package main

import (
	"fmt"

	"entgo.io/contrib/entoas"
	"entgo.io/ent/entc"
	"entgo.io/ent/entc/gen"
	eec "github.com/eidng8/go-ent/entc"
	"github.com/eidng8/go-ent/paginate"
	"github.com/eidng8/go-ent/softdelete"
	"github.com/ogen-go/ogen"

	"github.com/eidng8/go-attr-rbac/api"
)

// UsernamePasswordParams is sample schema for username and password sign-in.
var UsernamePasswordParams = ogen.Schema{
	Type: "object",
	Properties: []ogen.Property{
		{Name: "username", Schema: &ogen.Schema{Type: "string"}},
		{Name: "password", Schema: &ogen.Schema{Type: "string"}},
	},
	Required: []string{"username", "password"},
}

// UsernamePasswordParams is sample schema for email and password sign-in.
var EmailPasswordParams = ogen.Schema{
	Type: "object",
	Properties: []ogen.Property{
		{Name: "email", Schema: &ogen.Schema{Type: "string", Format: "email"}},
		{Name: "password", Schema: &ogen.Schema{Type: "string"}},
	},
	Required: []string{"username", "password"},
}

// UsernamePasswordParams is sample schema for token sign-in.
var TokenParams = ogen.Schema{
	Type: "object",
	Properties: []ogen.Property{
		{Name: "token", Schema: &ogen.Schema{Type: "string"}},
	},
	Required: []string{"username", "password"},
}

func main() {
	oas, err := newOasExtension()
	if err != nil {
		panic(err)
	}
	ext := entc.Extensions(oas, &eec.ClientExtension{})
	err = entc.Generate(
		"./ent/schema", &gen.Config{
			Features: []gen.Feature{
				gen.FeatureIntercept,
				gen.FeatureSnapshot, // remove this on first run
				gen.FeatureExecQuery,
				gen.FeatureVersionedMigration,
			},
		}, ext,
	)
	if err != nil {
		panic(err)
	}
}

func newOasExtension() (*entoas.Extension, error) {
	return entoas.NewExtension(
		entoas.Mutations(
			func(g *gen.Graph, s *ogen.Spec) error {
				editSpec(s)
				fixPaths(s)
				constraintRequestBody(s.Paths)
				fixTokenPaths(s)
				addHintOperations(s)
				addRoleOperations(s)
				err := addSoftDelete(s)
				if err != nil {
					return err
				}
				fixResponses(s)
				addPingPath(s)
				return nil
			},
		),
	)
}

func addHintOperations(s *ogen.Spec) {
	add := func(n1, n2, n3 string) {
		s.Paths[fmt.Sprintf("/q/%s", n1)] = &ogen.PathItem{
			Get: &ogen.Operation{
				Summary: fmt.Sprintf("quick search %s", n1),
				Description: fmt.Sprintf(
					"returns a few found %s with given prefix", n1,
				),
				OperationID: fmt.Sprintf("hint%s", n2),
				Parameters: []*ogen.Parameter{
					{
						Name:        "q",
						In:          "query",
						Description: "text to search",
						Required:    true,
						Schema:      &ogen.Schema{Type: "string"},
					},
				},
				Responses: map[string]*ogen.Response{
					"200": {
						Description: fmt.Sprintf("List of found %s", n1),
						Content: map[string]ogen.Media{
							"application/json": {
								Schema: &ogen.Schema{
									Type: "array",
									Items: &ogen.Items{
										Item: &ogen.Schema{
											Ref: fmt.Sprintf(
												"#/components/schemas/%sList",
												n3,
											),
										},
									},
								},
							},
						},
					},
					"400": {Ref: "#/components/responses/400"},
					"401": {Ref: "#/components/responses/401"},
					"403": {Ref: "#/components/responses/403"},
					"500": {Ref: "#/components/responses/500"},
				},
			},
		}
	}
	add("permissions", "Permissions", "Permission")
	add("roles", "Roles", "Role")
	add("users", "Users", "User")
}

func addPingPath(s *ogen.Spec) {
	s.Paths["/ping"] = &ogen.PathItem{
		Get: &ogen.Operation{
			Summary:     "Ping",
			Description: "Check if the service is running",
			OperationID: "ping",
			Responses: map[string]*ogen.Response{
				"204": {Description: "Service is running"},
				"500": {Ref: "#/components/responses/500"},
			},
		},
	}
}

func addRoleOperations(s *ogen.Spec) {
	s.Paths["/role/{id}/permissions"].Post = &ogen.Operation{
		Summary:     "Assign permissions to role",
		OperationID: "assignPermissions",
		Parameters: []*ogen.Parameter{
			{
				Name:        "id",
				In:          "path",
				Description: "ID of the role",
				Required:    true,
				Schema: &ogen.Schema{
					Type:    "integer",
					Format:  "uint32",
					Minimum: ogen.Num("1"),
				},
			},
		},
		RequestBody: &ogen.RequestBody{
			Required: true,
			Content: map[string]ogen.Media{
				"application/json": {
					Schema: &ogen.Schema{
						Type: "array",
						Items: &ogen.Items{
							Item: &ogen.Schema{
								Type:    "integer",
								Format:  "uint32",
								Minimum: ogen.Num("1"),
							},
						},
					},
				},
			},
		},
		Responses: map[string]*ogen.Response{
			"204": {Description: "Successfully assigned permissions to role"},
			"400": {Ref: "#/components/responses/400"},
			"401": {Ref: "#/components/responses/401"},
			"403": {Ref: "#/components/responses/403"},
			"500": {Ref: "#/components/responses/500"},
		},
	}
	s.Paths["/user/{id}/roles"].Post = &ogen.Operation{
		Summary:     "Assign roles to user",
		OperationID: "assignRoles",
		Parameters: []*ogen.Parameter{
			{
				Name:        "id",
				In:          "path",
				Description: "ID of the user",
				Required:    true,
				Schema: &ogen.Schema{
					Type:    "integer",
					Format:  "uint64",
					Minimum: ogen.Num("1"),
				},
			},
		},
		RequestBody: &ogen.RequestBody{
			Required: true,
			Content: map[string]ogen.Media{
				"application/json": {
					Schema: &ogen.Schema{
						Type: "array",
						Items: &ogen.Items{
							Item: &ogen.Schema{
								Type:    "integer",
								Format:  "uint32",
								Minimum: ogen.Num("1"),
							},
						},
					},
				},
			},
		},
		Responses: map[string]*ogen.Response{
			"204": {Description: "Successfully assigned roles to user"},
			"400": {Ref: "#/components/responses/400"},
			"401": {Ref: "#/components/responses/401"},
			"403": {Ref: "#/components/responses/403"},
			"500": {Ref: "#/components/responses/500"},
		},
	}
}

func addSoftDelete(s *ogen.Spec) error {
	err := softdelete.AttachTo(
		"user", s, "/user", s.Components.Schemas["UserRead"],
		findParamByName(s.Paths["/user/{id}"].Get.Parameters, "id"),
	)
	if err != nil {
		return err
	}
	return nil
}

func constraintRequestBody(paths ogen.Paths) {
	for _, path := range paths {
		if nil == path {
			continue
		}
		for _, op := range []*ogen.Operation{path.Put, path.Post, path.Patch} {
			if nil == op || nil == op.RequestBody || nil == op.RequestBody.Content {
				continue
			}
			for _, param := range op.RequestBody.Content {
				if nil == param.Schema {
					continue
				}
				b := false
				param.Schema.AdditionalProperties = &ogen.AdditionalProperties{Bool: &b}
			}
		}
	}
}

func editSpec(s *ogen.Spec) {
	s.Info.SetTitle("Simple authentication service").
		SetDescription("A simple authentication service of hybrid ABAC and RBAC").
		SetVersion("0.0.1")
}

func findParamByName(Params []*ogen.Parameter, name string) *ogen.Parameter {
	for _, p := range Params {
		if p.Name == name {
			return p
		}
	}
	return nil
}

func fixPaths(spec *ogen.Spec) {
	spec.Paths["/permission/{id}"] = spec.Paths["/permissions/{id}"]
	delete(spec.Paths, "/permissions/{id}")
	spec.Paths["/personal-token/{id}"] = spec.Paths["/personal-tokens/{id}"]
	delete(spec.Paths, "/personal-tokens/{id}")
	spec.Paths["/role/{id}"] = spec.Paths["/roles/{id}"]
	delete(spec.Paths, "/roles/{id}")
	spec.Paths["/role/{id}/permissions"] = spec.Paths["/roles/{id}/permissions"]
	delete(spec.Paths, "/roles/{id}/permissions")
	spec.Paths["/role/{id}/users"] = spec.Paths["/roles/{id}/users"]
	delete(spec.Paths, "/roles/{id}/users")
	spec.Paths["/user/{id}"] = spec.Paths["/users/{id}"]
	delete(spec.Paths, "/users/{id}")
	spec.Paths["/user/{id}/roles"] = spec.Paths["/users/{id}/roles"]
	delete(spec.Paths, "/users/{id}/roles")

	u2 := uint64(2)
	u255 := uint64(255)
	spec.Paths["/permission/{id}"].Get.AddParameters(
		&ogen.Parameter{
			Name:        "username",
			In:          "query",
			Description: "Username of the user",
			Required:    false,
			Schema: &ogen.Schema{
				Type:      "string",
				MinLength: &u2,
				MaxLength: &u255,
			},
		},
	)
	permissionParam := nameParam("permission")
	roleParam := nameParam("role")
	namParam := nameParam("user")
	spec.Paths["/permissions"].Get.AddParameters(permissionParam)
	spec.Paths["/roles"].Get.AddParameters(roleParam)
	spec.Paths["/users"].Get.AddParameters(namParam)

	permissionListRef := spec.Paths["/permissions"].Get.Responses["200"].
		Content["application/json"].Schema.Items.Item.Ref
	paginate.AttachTo(
		spec.Paths["/permissions"].Get,
		"Paginated list of permissions",
		permissionListRef,
	)
	paginate.AttachTo(
		spec.Paths["/personal-tokens"].Get,
		"Paginated list of issued personal access tokens",
		spec.Paths["/personal-tokens"].Get.Responses["200"].
			Content["application/json"].Schema.Items.Item.Ref,
	)
	roleListRef := spec.Paths["/roles"].Get.Responses["200"].
		Content["application/json"].Schema.Items.Item.Ref
	paginate.AttachTo(
		spec.Paths["/roles"].Get,
		"Paginated list of attached roles",
		roleListRef,
	)
	roleUsersListRef := spec.Paths["/role/{id}/users"].Get.Responses["200"].
		Content["application/json"].Schema.Items.Item.Ref
	paginate.AttachTo(
		spec.Paths["/role/{id}/users"].Get,
		"Paginated list of attached role users",
		roleUsersListRef,
	)
	rolePermissionsListRef := spec.Paths["/role/{id}/permissions"].Get.
		Responses["200"].Content["application/json"].Schema.Items.Item.Ref
	paginate.AttachTo(
		spec.Paths["/role/{id}/permissions"].Get,
		"Paginated list of attached role permissions",
		rolePermissionsListRef,
	)
	userListRef := spec.Paths["/users"].Get.Responses["200"].
		Content["application/json"].Schema.Items.Item.Ref
	paginate.AttachTo(
		spec.Paths["/users"].Get,
		"Paginated list of attached users", userListRef,
	)
	userRolesListRef := spec.Paths["/user/{id}/roles"].Get.Responses["200"].
		Content["application/json"].Schema.Items.Item.Ref
	paginate.AttachTo(
		spec.Paths["/user/{id}/roles"].Get,
		"Paginated list of attached user roles", userRolesListRef,
	)
}

func fixResponses(spec *ogen.Spec) {
	spec.Paths["/permissions"].Post.Responses["201"] =
		spec.Paths["/permissions"].Post.Responses["200"]
	delete(spec.Paths["/permissions"].Post.Responses, "200")
	spec.Paths["/personal-tokens"].Post.Responses["201"] =
		spec.Paths["/personal-tokens"].Post.Responses["200"]
	delete(spec.Paths["/personal-tokens"].Post.Responses, "200")
	spec.Paths["/roles"].Post.Responses["201"] =
		spec.Paths["/roles"].Post.Responses["200"]
	delete(spec.Paths["/roles"].Post.Responses, "200")
	spec.Paths["/users"].Post.Responses["201"] =
		spec.Paths["/users"].Post.Responses["200"]
	delete(spec.Paths["/users"].Post.Responses, "200")
	spec.Components.Responses["401"].Content =
		spec.Components.Responses["403"].Content
	for _, path := range spec.Paths {
		if nil == path {
			continue
		}
		for _, op := range []*ogen.Operation{
			path.Get, path.Post, path.Put, path.Patch, path.Delete,
		} {
			if nil == op {
				continue
			}
			if nil == op.Responses["401"] {
				op.AddResponse(
					"401", &ogen.Response{Ref: "#/components/responses/401"},
				)
			}
			if nil == op.Responses["403"] {
				op.AddResponse(
					"403", &ogen.Response{Ref: "#/components/responses/403"},
				)
			}
		}
	}
}

func fixTokenPaths(spec *ogen.Spec) {
	spec.Components.Responses["401"] = &ogen.Response{
		Description: "Unauthorized",
	}
	spec.Components.Schemas["LongLivedToken"] = &ogen.Schema{
		Type: "object",
		Properties: []ogen.Property{
			{Name: "name", Schema: &ogen.Schema{Type: "string"}},
			{Name: "token", Schema: &ogen.Schema{Type: "string"}},
			{
				Name:   "created_at",
				Schema: &ogen.Schema{Type: "string", Format: "date-time"},
			},
		},
		Required: []string{"name", "token"},
	}
	delete(spec.Paths, "/access-tokens")
	spec.Paths["/access-token"] = spec.Paths["/access-tokens/{id}"]
	delete(spec.Paths, "/access-tokens/{id}")
	spec.Paths["/access-token"].Get.SetOperationID("checkAccessToken")
	spec.Paths["/access-token"].Get.SetParameters(nil)
	spec.Paths["/access-token"].Get.SetSummary("Validate current access token")
	spec.Paths["/access-token"].Get.SetDescription("")
	delete(spec.Paths["/access-token"].Get.Responses, "200")
	delete(spec.Paths["/access-token"].Get.Responses, "404")
	delete(spec.Paths["/access-token"].Get.Responses, "409")
	spec.Paths["/access-token"].Get.AddResponse(
		"204", &ogen.Response{
			Description: "Successfully validated access token",
		},
	)
	spec.Paths["/access-token"].Patch.SetOperationID("refreshAccessToken")
	spec.Paths["/access-token"].Patch.SetParameters(nil)
	spec.Paths["/access-token"].Patch.SetRequestBody(nil)
	spec.Paths["/access-token"].Patch.SetSummary("Refresh current access token")
	spec.Paths["/access-token"].Patch.
		SetDescription("Refresh current access token using refresh token")
	delete(spec.Paths["/access-token"].Patch.Responses, "200")
	delete(spec.Paths["/access-token"].Patch.Responses, "404")
	delete(spec.Paths["/access-token"].Patch.Responses, "409")
	spec.Paths["/access-token"].Patch.AddResponse(
		"204", &ogen.Response{
			Description: "Successfully refreshed access token",
		},
	)
	spec.AddPathItem(
		api.RefreshTokenPath,
		&ogen.PathItem{Post: spec.Paths["/access-token"].Patch},
	)
	spec.Paths["/access-token"].Patch = nil
	spec.Paths["/access-token"].Delete.SetOperationID("revokeAccessToken")
	spec.Paths["/access-token"].Delete.SetParameters(nil)
	spec.Paths["/access-token"].Delete.SetSummary("Revoke current access token")
	spec.Paths["/access-token"].Delete.
		SetDescription("Revoke current access token and refresh token")
	delete(spec.Paths["/access-token"].Delete.Responses, "404")
	delete(spec.Paths["/access-token"].Delete.Responses, "409")
	spec.Paths["/access-token"].Delete.Responses["204"].
		SetDescription("Successfully revoked access token")
	spec.Paths["/personal-token/{id}"].SetPatch(nil)
	spec.Paths["/login"] = &ogen.PathItem{
		Post: &ogen.Operation{
			Summary:     "Login",
			Description: "Authenticate a user and return a token",
			OperationID: "login",
			RequestBody: &ogen.RequestBody{
				Required: true,
				Content: map[string]ogen.Media{
					"application/json": {Schema: &UsernamePasswordParams},
				},
			},
			Responses: map[string]*ogen.Response{
				"200": {
					Description: "Successfully authenticated",
					Content: map[string]ogen.Media{
						"application/json": {
							Schema: &ogen.Schema{
								Ref: spec.Paths["/user/{id}"].Get.
									Responses["200"].
									Content["application/json"].
									Schema.Ref,
							},
						},
					},
				},
				"400": {Ref: "#/components/responses/400"},
				// "401": {Ref: "#/components/responses/401"},
				"500": {Ref: "#/components/responses/500"},
			},
		},
	}
	spec.Paths["/logout"] = &ogen.PathItem{
		Post: &ogen.Operation{
			Summary:     "Logout",
			Description: "Invalidate the user's access token",
			OperationID: "logout",
			Responses: map[string]*ogen.Response{
				"204": {Description: "Successfully logged out"},
				"500": {Ref: "#/components/responses/500"},
			},
		},
	}
}

func nameParam(subject string) *ogen.Parameter {
	u2 := uint64(2)
	u255 := uint64(255)
	return &ogen.Parameter{
		Name:        "name",
		In:          "query",
		Description: "Name of the " + subject,
		Required:    false,
		Schema: &ogen.Schema{
			Type:      "string",
			MinLength: &u2,
			MaxLength: &u255,
		},
	}
}
