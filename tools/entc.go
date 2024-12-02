//go:build ignore
// +build ignore

package main

import (
	"entgo.io/contrib/entoas"
	"entgo.io/ent/entc"
	"entgo.io/ent/entc/gen"
	ee "github.com/eidng8/go-ent"
	"github.com/eidng8/go-ent/paginate"
	"github.com/eidng8/go-ent/softdelete"
	"github.com/ogen-go/ogen"
)

var UsernamePasswordParams = ogen.Schema{
	Type: "object",
	Properties: []ogen.Property{
		{Name: "username", Schema: &ogen.Schema{Type: "string"}},
		{Name: "password", Schema: &ogen.Schema{Type: "string"}},
	},
	Required: []string{"username", "password"},
}

var EmailPasswordParams = ogen.Schema{
	Type: "object",
	Properties: []ogen.Property{
		{Name: "email", Schema: &ogen.Schema{Type: "string", Format: "email"}},
		{Name: "password", Schema: &ogen.Schema{Type: "string"}},
	},
	Required: []string{"username", "password"},
}

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
	ext := entc.Extensions(oas, &ee.Extension{})
	err = entc.Generate("./ent/schema", genConfig(), ext)
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
				err := addSoftDelete(s)
				if err != nil {
					return err
				}
				fixTokenPaths(s)
				fixResponses(s)
				return nil
			},
		),
	)
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
	// spec.Paths["/access-token"].Get.AddResponse(
	//     "401", &ogen.Response{Ref: "#/components/responses/401"},
	// )
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
	// spec.Paths["/access-token"].Patch.AddResponse(
	//     "401", &ogen.Response{Ref: "#/components/responses/401"},
	// )
	spec.Paths["/access-token"].Delete.SetOperationID("revokeAccessToken")
	spec.Paths["/access-token"].Delete.SetParameters(nil)
	spec.Paths["/access-token"].Delete.SetSummary("Revoke current access token")
	spec.Paths["/access-token"].Delete.
		SetDescription("Revoke current access token and refresh token")
	delete(spec.Paths["/access-token"].Delete.Responses, "404")
	delete(spec.Paths["/access-token"].Delete.Responses, "409")
	spec.Paths["/access-token"].Delete.Responses["204"].
		SetDescription("Successfully revoked access token")
	spec.Paths["/personal-tokens/{id}"].SetPatch(nil)
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

func findParamByName(Params []*ogen.Parameter, name string) *ogen.Parameter {
	for _, p := range Params {
		if p.Name == name {
			return p
		}
	}
	return nil
}

func genConfig() *gen.Config {
	return &gen.Config{
		Features: []gen.Feature{
			gen.FeatureIntercept,
			gen.FeatureSnapshot,
			gen.FeatureExecQuery,
			gen.FeatureVersionedMigration,
		},
	}
}

func editSpec(s *ogen.Spec) {
	s.Info.SetTitle("Simple authentication service").
		SetDescription("A simple authentication service of hybrid ABAC and RBAC").
		SetVersion("0.0.1")
}

func fixComponents(spec *ogen.Spec) {
	delete(spec.Components.Schemas, "RolePermission")
	delete(spec.Components.Schemas, "RolePermission_PermissionRead")
}

func fixPaths(spec *ogen.Spec) {
	spec.Paths["/permission/{id}"] = spec.Paths["/permissions/{id}"]
	delete(spec.Paths, "/permissions/{id}")
	spec.Paths["/role/{id}"] = spec.Paths["/roles/{id}"]
	delete(spec.Paths, "/roles/{id}")
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
	// spec.Paths["/permission/{id}/roles"].Get.AddParameters(roleParam)
	spec.Paths["/roles"].Get.AddParameters(roleParam)
	// spec.Paths["/role/{id}/permissions"].Get.AddParameters(permissionParam)
	// spec.Paths["/role/{id}/users"].Get.AddParameters(namParam)
	spec.Paths["/users"].Get.AddParameters(namParam)
	// spec.Paths["/user/{id}/roles"].Get.AddParameters(roleParam)

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
	roleUsersListRef := spec.Paths["/roles/{id}/users"].Get.Responses["200"].
		Content["application/json"].Schema.Items.Item.Ref
	paginate.AttachTo(
		spec.Paths["/roles/{id}/users"].Get,
		"Paginated list of attached role users",
		roleUsersListRef,
	)
	rolePermissionsListRef := spec.Paths["/roles/{id}/permissions"].Get.
		Responses["200"].Content["application/json"].Schema.Items.Item.Ref
	paginate.AttachTo(
		spec.Paths["/roles/{id}/permissions"].Get,
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

	// delete(spec.Components.Schemas, "RolePermission_PermissionRead")
	// delete(spec.Components.Schemas, "RolePermission_RoleRead")
	// delete(spec.Components.Schemas, "UserRole_RoleRead")
	// delete(spec.Components.Schemas, "UserRole_UserRead")
}

func fixResponses(spec *ogen.Spec) {
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
			op.AddResponse(
				"401", &ogen.Response{Ref: "#/components/responses/401"},
			)
		}
	}
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
