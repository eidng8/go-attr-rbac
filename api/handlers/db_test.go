package handlers

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/migrate"
	"github.com/eidng8/go-attr-rbac/ent/role"
	"github.com/eidng8/go-attr-rbac/ent/user"
)

func fixture(tb testing.TB, client *ent.Client) {
	qc := context.Background()
	err := client.Schema.Create(
		qc, migrate.WithDropIndex(true), migrate.WithDropColumn(true),
		migrate.WithForeignKeys(true),
	)
	require.Nil(tb, err)
	ids := make([]uint32, numFixtures)
	roles := make([]*ent.RoleCreate, numFixtures)
	users := make([]*ent.UserCreate, numFixtures)
	for i := range numFixtures {
		ids[i] = uint32(i + 1)
		roles[i] = client.Role.Create().SetName(fmt.Sprintf("role %d", i)).
			SetDescription(fmt.Sprintf("role %d description", i))
		users[i] = client.User.Create().SetUsername(fmt.Sprintf("user%d", i)).
			SetEmail(fmt.Sprintf("email%d@test.com", i)).
			SetPassword(fmt.Sprintf("password%d", i)).
			SetAttr(&map[string]interface{}{"dept": i + 1, "level": i + 5})
	}
	client.Role.CreateBulk(roles...).SaveX(qc)
	client.User.CreateBulk(users...).SaveX(qc)
	client.Role.Update().Where(role.IDEQ(2)).AddPermissionIDs(2, 3, 4).ExecX(qc)
	client.User.Update().Where(user.IDEQ(2)).AddRoleIDs(2, 3, 4).ExecX(qc)
}

// Gets the user from database. Does NOT eagerly load anything.
func getUserById(tb testing.TB, db *ent.Client, id uint64) *ent.User {
	u, err := db.User.Query().Where(user.IDEQ(id)).Only(context.Background())
	require.Nil(tb, err)
	return u
}

func pluckPermissionId(row *ent.Permission) uint32 { return row.ID }

func pluckRoleId(row *ent.Role) uint32 { return row.ID }
