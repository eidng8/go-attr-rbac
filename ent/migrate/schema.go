// Code generated by ent, DO NOT EDIT.

package migrate

import (
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/dialect/sql/schema"
	"entgo.io/ent/schema/field"
)

var (
	// AccessTokensColumns holds the columns for the "access_tokens" table.
	AccessTokensColumns = []*schema.Column{
		{Name: "id", Type: field.TypeUint64, Increment: true},
		{Name: "user_id", Type: field.TypeUint64},
		{Name: "access_token", Type: field.TypeBytes, Unique: true, SchemaType: map[string]string{"mysql": "binary(16)", "postgres": "binary(16)", "sqlite3": "blob"}},
		{Name: "refresh_token", Type: field.TypeBytes, Unique: true, SchemaType: map[string]string{"mysql": "binary(16)", "postgres": "binary(16)", "sqlite3": "blob"}},
		{Name: "created_at", Type: field.TypeTime, Nullable: true},
		{Name: "user_access_tokens", Type: field.TypeUint64, Nullable: true},
		{Name: "user_refresh_tokens", Type: field.TypeUint64, Nullable: true},
	}
	// AccessTokensTable holds the schema information for the "access_tokens" table.
	AccessTokensTable = &schema.Table{
		Name:       "access_tokens",
		Columns:    AccessTokensColumns,
		PrimaryKey: []*schema.Column{AccessTokensColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "access_tokens_users_access_tokens",
				Columns:    []*schema.Column{AccessTokensColumns[5]},
				RefColumns: []*schema.Column{UsersColumns[0]},
				OnDelete:   schema.Restrict,
			},
			{
				Symbol:     "access_tokens_users_refresh_tokens",
				Columns:    []*schema.Column{AccessTokensColumns[6]},
				RefColumns: []*schema.Column{UsersColumns[0]},
				OnDelete:   schema.Restrict,
			},
		},
	}
	// PermissionsColumns holds the columns for the "permissions" table.
	PermissionsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeUint32, Increment: true},
		{Name: "name", Type: field.TypeString, Unique: true},
		{Name: "description", Type: field.TypeString, Nullable: true},
		{Name: "created_at", Type: field.TypeTime, Nullable: true},
		{Name: "updated_at", Type: field.TypeTime, Nullable: true},
	}
	// PermissionsTable holds the schema information for the "permissions" table.
	PermissionsTable = &schema.Table{
		Name:       "permissions",
		Columns:    PermissionsColumns,
		PrimaryKey: []*schema.Column{PermissionsColumns[0]},
	}
	// PersonalTokensColumns holds the columns for the "personal_tokens" table.
	PersonalTokensColumns = []*schema.Column{
		{Name: "id", Type: field.TypeUint64, Increment: true},
		{Name: "user_id", Type: field.TypeUint64},
		{Name: "description", Type: field.TypeString},
		{Name: "token", Type: field.TypeBytes, Unique: true, SchemaType: map[string]string{"mysql": "binary(16)", "postgres": "binary(16)", "sqlite3": "blob"}},
		{Name: "created_at", Type: field.TypeTime, Nullable: true},
		{Name: "user_personal_tokens", Type: field.TypeUint64, Nullable: true},
	}
	// PersonalTokensTable holds the schema information for the "personal_tokens" table.
	PersonalTokensTable = &schema.Table{
		Name:       "personal_tokens",
		Comment:    "Stores issued long-lived tokens",
		Columns:    PersonalTokensColumns,
		PrimaryKey: []*schema.Column{PersonalTokensColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "personal_tokens_users_personal_tokens",
				Columns:    []*schema.Column{PersonalTokensColumns[5]},
				RefColumns: []*schema.Column{UsersColumns[0]},
				OnDelete:   schema.Restrict,
			},
		},
	}
	// RolesColumns holds the columns for the "roles" table.
	RolesColumns = []*schema.Column{
		{Name: "id", Type: field.TypeUint32, Increment: true},
		{Name: "name", Type: field.TypeString, Unique: true},
		{Name: "description", Type: field.TypeString, Nullable: true},
		{Name: "created_at", Type: field.TypeTime, Nullable: true},
		{Name: "updated_at", Type: field.TypeTime, Nullable: true},
	}
	// RolesTable holds the schema information for the "roles" table.
	RolesTable = &schema.Table{
		Name:       "roles",
		Columns:    RolesColumns,
		PrimaryKey: []*schema.Column{RolesColumns[0]},
	}
	// UsersColumns holds the columns for the "users" table.
	UsersColumns = []*schema.Column{
		{Name: "id", Type: field.TypeUint64, Increment: true},
		{Name: "deleted_at", Type: field.TypeTime, Nullable: true},
		{Name: "username", Type: field.TypeString, Unique: true},
		{Name: "email", Type: field.TypeString, Unique: true, Nullable: true},
		{Name: "password", Type: field.TypeString},
		{Name: "attr", Type: field.TypeJSON, Nullable: true},
		{Name: "created_at", Type: field.TypeTime, Nullable: true},
		{Name: "updated_at", Type: field.TypeTime, Nullable: true},
	}
	// UsersTable holds the schema information for the "users" table.
	UsersTable = &schema.Table{
		Name:       "users",
		Columns:    UsersColumns,
		PrimaryKey: []*schema.Column{UsersColumns[0]},
	}
	// RolePermissionsColumns holds the columns for the "role_permissions" table.
	RolePermissionsColumns = []*schema.Column{
		{Name: "role_id", Type: field.TypeUint32},
		{Name: "permission_id", Type: field.TypeUint32},
	}
	// RolePermissionsTable holds the schema information for the "role_permissions" table.
	RolePermissionsTable = &schema.Table{
		Name:       "role_permissions",
		Columns:    RolePermissionsColumns,
		PrimaryKey: []*schema.Column{RolePermissionsColumns[0], RolePermissionsColumns[1]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "role_permissions_role_id",
				Columns:    []*schema.Column{RolePermissionsColumns[0]},
				RefColumns: []*schema.Column{RolesColumns[0]},
				OnDelete:   schema.Cascade,
			},
			{
				Symbol:     "role_permissions_permission_id",
				Columns:    []*schema.Column{RolePermissionsColumns[1]},
				RefColumns: []*schema.Column{PermissionsColumns[0]},
				OnDelete:   schema.Cascade,
			},
		},
	}
	// RoleUsersColumns holds the columns for the "role_users" table.
	RoleUsersColumns = []*schema.Column{
		{Name: "role_id", Type: field.TypeUint32},
		{Name: "user_id", Type: field.TypeUint64},
	}
	// RoleUsersTable holds the schema information for the "role_users" table.
	RoleUsersTable = &schema.Table{
		Name:       "role_users",
		Columns:    RoleUsersColumns,
		PrimaryKey: []*schema.Column{RoleUsersColumns[0], RoleUsersColumns[1]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "role_users_role_id",
				Columns:    []*schema.Column{RoleUsersColumns[0]},
				RefColumns: []*schema.Column{RolesColumns[0]},
				OnDelete:   schema.Cascade,
			},
			{
				Symbol:     "role_users_user_id",
				Columns:    []*schema.Column{RoleUsersColumns[1]},
				RefColumns: []*schema.Column{UsersColumns[0]},
				OnDelete:   schema.Cascade,
			},
		},
	}
	// Tables holds all the tables in the schema.
	Tables = []*schema.Table{
		AccessTokensTable,
		PermissionsTable,
		PersonalTokensTable,
		RolesTable,
		UsersTable,
		RolePermissionsTable,
		RoleUsersTable,
	}
)

func init() {
	AccessTokensTable.ForeignKeys[0].RefTable = UsersTable
	AccessTokensTable.ForeignKeys[1].RefTable = UsersTable
	AccessTokensTable.Annotation = &entsql.Annotation{}
	PermissionsTable.Annotation = &entsql.Annotation{}
	PersonalTokensTable.ForeignKeys[0].RefTable = UsersTable
	PersonalTokensTable.Annotation = &entsql.Annotation{}
	RolesTable.Annotation = &entsql.Annotation{}
	UsersTable.Annotation = &entsql.Annotation{}
	RolePermissionsTable.ForeignKeys[0].RefTable = RolesTable
	RolePermissionsTable.ForeignKeys[1].RefTable = PermissionsTable
	RolePermissionsTable.Annotation = &entsql.Annotation{}
	RoleUsersTable.ForeignKeys[0].RefTable = RolesTable
	RoleUsersTable.ForeignKeys[1].RefTable = UsersTable
	RoleUsersTable.Annotation = &entsql.Annotation{}
}