package api

import (
	"context"
	"fmt"
	"slices"

	"github.com/eidng8/go-utils"
	"golang.org/x/crypto/bcrypt"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/migrate"
	"github.com/eidng8/go-attr-rbac/ent/permission"
	"github.com/eidng8/go-attr-rbac/ent/role"
	"github.com/eidng8/go-attr-rbac/ent/user"
)

// dbSetup makes sure we have a database with at least preliminary data.
func dbSetup(c *ent.Client) {
	Log.Infof("Checking whether database has preliminary data...")
	qc := context.Background()

	// check schema
	err := c.Schema.Create(
		qc, migrate.WithDropIndex(true),
		migrate.WithDropColumn(true), migrate.WithForeignKeys(true),
	)
	utils.PanicIfError(err)

	// check preliminary permissions
	perms := []string{
		"RevokeAccessToken", "CheckAccessToken", "RefreshAccessToken", "Login",
		"Logout", "DeletePermission", "ReadPermission", "UpdatePermission",
		"ListPermission", "CreatePermission", "DeletePersonalToken",
		"ReadPersonalToken", "ListPersonalToken", "CreatePersonalToken", "Ping",
		"HintPermissions", "HintRoles", "HintUsers", "DeleteRole", "ReadRole",
		"UpdateRole", "ListRolePermissions", "AssignPermissions",
		"ListRoleUsers", "ListRole", "CreateRole", "DeleteUser", "ReadUser",
		"UpdateUser", "RestoreUser", "ListUserRoles", "AssignRoles", "ListUser",
		"CreateUser",
	}
	rows := c.Permission.Query().Where(permission.NameIn(perms...)).
		Select(permission.FieldName).AllX(qc)
	existing := utils.Pluck(
		rows, func(p *ent.Permission) string { return p.Name },
	)
	add := slices.DeleteFunc(
		perms, func(p string) bool { return slices.Contains(existing, p) },
	)
	count := len(add)
	if count > 0 {
		p := make([]*ent.PermissionCreate, count)
		for i, a := range add {
			p[i] = c.Permission.Create().SetName("auth:" + a)
		}
		c.Permission.CreateBulk(p...).ExecX(qc)
	}

	// make root role exists, don't do anything if it exists
	r := c.Role.Query().Where(role.IDEQ(1)).FirstX(qc)
	if nil == r {
		r = c.Role.Create().SetID(1).SetName("root").SaveX(qc)
		_, err := c.Transaction(
			qc, func(qc context.Context, tx *ent.Tx) (interface{}, error) {
				//goland:noinspection SqlNoDataSourceInspection,SqlResolve
				return tx.ExecContext(
					qc,
					fmt.Sprintf(
						"INSERT INTO `%s`(`%s`,`%s`) SELECT 1,`%s` FROM `%s`",
						role.PermissionsTable, role.PermissionsPrimaryKey[0],
						role.PermissionsPrimaryKey[1], permission.FieldID,
						permission.Table,
					),
				)
			},
		)
		utils.PanicIfError(err)
	}

	// make sure root user exists and has root role
	u := c.User.Query().Where(user.IDEQ(1)).FirstX(qc)
	if nil == u {
		// generate a random 32-character password
		pass, err := utils.RandomPrintable(32)
		utils.PanicIfError(err)
		hash, err := hashPassword(pass)
		utils.PanicIfError(err)
		u = c.User.Create().SetID(1).SetUsername("root").
			SetPassword(hash).SaveX(qc)
	}
	if !u.QueryRoles().Where(role.IDEQ(1)).ExistX(qc) {
		u.Update().AddRoleIDs(1).ExecX(qc)
	}
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password), bcrypt.DefaultCost,
	)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
