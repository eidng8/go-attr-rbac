package handlers

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	// _ "github.com/go-sql-driver/mysql"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/api"
	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/enttest"
	"github.com/eidng8/go-attr-rbac/ent/migrate"
	"github.com/eidng8/go-attr-rbac/ent/role"
	"github.com/eidng8/go-attr-rbac/ent/user"
)

var testdb *ent.Client

func setup(tb testing.TB, freshDb bool) (
	*Server, *gin.Engine, *ent.Client, *httptest.ResponseRecorder,
) {
	api.Log.Debug = true
	require.Nil(tb, os.Setenv(api.BaseUrlName, "http://localhost"))
	require.Nil(tb, os.Setenv(api.PrivateKeyName, buildSecret(32)))
	require.Nil(tb, os.Setenv(api.PublicOpsName, "ping"))
	if freshDb || nil == testdb {
		if nil != testdb {
			require.Nil(tb, testdb.Close())
		}
		// testdb = enttest.Open(
		//     tb, "mysql",
		//     "root:123456@tcp(localhost:32768)/testdb?parseTime=True",
		// )
		testdb = enttest.Open(tb, "sqlite3", ":memory:?_fk=1")
	}
	tb.Cleanup(
		func() {
			if freshDb {
				require.Nil(tb, testdb.Close())
				testdb = nil
			}
		},
	)
	server, engine, err := NewEngine(testdb)
	require.Nil(tb, err)
	fixture(tb, testdb)
	return server, engine, testdb, httptest.NewRecorder()

}

func buildSecret(width int) string {
	bytes := make([]byte, width)
	for i := range width {
		bytes[i] = byte(rand.UintN(256))
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

func fixture(tb testing.TB, client *ent.Client) {
	qc := context.Background()
	err := client.Schema.Create(
		qc, migrate.WithDropIndex(true), migrate.WithDropColumn(true),
		migrate.WithForeignKeys(true),
	)
	require.Nil(tb, err)
	ids := make([]uint32, 50)
	roles := make([]*ent.RoleCreate, 50)
	users := make([]*ent.UserCreate, 50)
	for i := range 50 {
		ids[i] = uint32(i + 1)
		roles[i] = client.Role.Create().SetName(fmt.Sprintf("role %d", i))
		users[i] = client.User.Create().SetUsername(fmt.Sprintf("user%d", i)).
			SetEmail(fmt.Sprintf("email%d@test.com", i)).
			SetPassword(fmt.Sprintf("password%d", i)).
			SetAttr(&map[string]interface{}{"dept": i + 1, "level": i + 5})
	}
	client.Role.CreateBulk(roles...).SaveX(qc)
	client.User.CreateBulk(users...).SaveX(qc)
	client.Role.Update().Where(role.IDEQ(2)).AddPermissionIDs(1, 2, 3).ExecX(qc)
	client.User.Update().Where(user.IDEQ(2)).AddRoleIDs(1, 2, 3).ExecX(qc)
}

func getUserById(tb testing.TB, db *ent.Client, id uint64) *ent.User {
	u, err := db.User.Query().Where(user.IDEQ(id)).Only(context.Background())
	require.Nil(tb, err)
	return u
}

func pluckPermissionId(row *ent.Permission) uint32 { return row.ID }

func (s Server) requestAs(
	tb testing.TB, usr *ent.User, method string, url string, body io.Reader,
) *http.Request {
	req, err := http.NewRequest(method, url, body)
	require.Nil(tb, err)
	at, err := s.issueAccessToken(usr)
	require.Nil(tb, err)
	req.AddCookie(
		&http.Cookie{
			Name:     accessTokenName,
			Value:    at,
			Path:     "/",
			Domain:   s.Domain(),
			MaxAge:   3600,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		},
	)
	req.AddCookie(
		&http.Cookie{
			Name:     refreshTokenName,
			Value:    at,
			Path:     api.RefreshTokenPath,
			Domain:   s.Domain(),
			MaxAge:   3600,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		},
	)
	return req
}
