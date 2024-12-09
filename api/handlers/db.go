package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"slices"

	"github.com/eidng8/go-utils"
	"golang.org/x/crypto/argon2"

	"github.com/eidng8/go-attr-rbac/api"
	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/migrate"
	"github.com/eidng8/go-attr-rbac/ent/permission"
	"github.com/eidng8/go-attr-rbac/ent/role"
	"github.com/eidng8/go-attr-rbac/ent/user"
)

// dbSetup makes sure we have a database with at least preliminary data.
func dbSetup(c *ent.Client, params PasswordHashParams) {
	api.Log.Infof("Checking whether database has preliminary data...")
	qc := context.Background()

	// check schema
	err := c.Schema.Create(
		qc, migrate.WithDropIndex(true),
		migrate.WithDropColumn(true), migrate.WithForeignKeys(true),
	)
	utils.PanicIfError(err)

	// check preliminary permissions
	perms := []string{
		"auth:RevokeAccessToken",
		"auth:CheckAccessToken",
		"auth:RefreshAccessToken",
		"auth:Login",
		"auth:Logout",
		"auth:DeletePermission",
		"auth:ReadPermission",
		"auth:UpdatePermission",
		"auth:ListPermission",
		"auth:CreatePermission",
		"auth:DeletePersonalToken",
		"auth:ReadPersonalToken",
		"auth:ListPersonalToken",
		"auth:CreatePersonalToken",
		"auth:Ping",
		"auth:HintPermissions",
		"auth:HintRoles",
		"auth:HintUsers",
		"auth:DeleteRole",
		"auth:ReadRole",
		"auth:UpdateRole",
		"auth:ListRolePermissions",
		"auth:AssignPermissions",
		"auth:ListRoleUsers",
		"auth:ListRole",
		"auth:CreateRole",
		"auth:DeleteUser",
		"auth:ReadUser",
		"auth:UpdateUser",
		"auth:RestoreUser",
		"auth:ListUserRoles",
		"auth:AssignRoles",
		"auth:ListUser",
		"auth:CreateUser",
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
			p[i] = c.Permission.Create().SetName(a)
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
		hash, err := hashPassword(pass, params)
		utils.PanicIfError(err)
		u = c.User.Create().SetID(1).SetUsername("root").
			SetPassword(hash).
			SetAttr(&map[string]interface{}{"dept": 1, "level": 1}).
			SaveX(qc)
	}
	if !u.QueryRoles().Where(role.IDEQ(1)).ExistX(qc) {
		u.Update().AddRoleIDs(1).ExecX(qc)
	}

	// makes the password column completely hidden, explicit select must be used
	// to get the password
	for i, f := range user.Columns {
		if user.FieldPassword == f {
			user.Columns = slices.Delete(user.Columns, i, i+1)
			break
		}
	}
}

func hashPassword(password string, params PasswordHashParams) (string, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey(
		[]byte(password), salt,
		params.Times, params.Memory, params.Threads, params.KeyLen,
	)
	return base64.StdEncoding.EncodeToString(hash), nil
}
