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
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/api"
	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/enttest"
	"github.com/eidng8/go-attr-rbac/ent/migrate"
	"github.com/eidng8/go-attr-rbac/ent/role"
	"github.com/eidng8/go-attr-rbac/ent/user"
)

const numFixtures = 10

var (
	testdb    *ent.Client
	startTime = time.Now()
)

// Creates a new server, engine, and client for testing.
// If there were no previously connected database, this function will create a
// new database for testing populated with fixture data. If `refresh` is true,
// the database will be closed after the test; otherwise the database will
// be left open for further testing.
func setup(tb testing.TB, refresh bool) (
	*Server, *gin.Engine, *ent.Client, *httptest.ResponseRecorder,
) {
	api.Log.Debug = true
	nrd := nil == testdb
	require.Nil(tb, os.Setenv(api.BaseUrlName, "http://localhost"))
	require.Nil(tb, os.Setenv(api.PrivateKeyName, buildSecret(32)))
	require.Nil(tb, os.Setenv(api.PublicOpsName, "ping"))
	if nrd {
		// testdb = enttest.Open(
		//     tb, "mysql",
		//     "root:123456@tcp(localhost:32768)/testdb?parseTime=True",
		// )
		testdb = enttest.Open(tb, "sqlite3", ":memory:?_fk=1")
	}
	tb.Cleanup(
		func() {
			if refresh {
				tmp := testdb
				testdb = nil
				require.Nil(tb, tmp.Close())
			}
		},
	)
	server, engine, err := NewEngine(testdb)
	if nrd {
		fixture(tb, testdb)
	}
	require.Nil(tb, err)
	startTime = time.Now()
	return server, engine, testdb, httptest.NewRecorder()
}

func (s Server) get(url string) (*http.Request, error) {
	return s.getAs(nil, url)
}

func (s Server) getAs(usr *ent.User, url string) (*http.Request, error) {
	return s.request(usr, http.MethodGet, url, nil)
}

func (s Server) post(url string, body interface{}) (*http.Request, error) {
	return s.postAs(nil, url, body)
}

func (s Server) postAs(usr *ent.User, url string, body interface{}) (
	*http.Request, error,
) {
	return s.request(usr, http.MethodPost, url, body)
}

func (s Server) patch(url string, body interface{}) (*http.Request, error) {
	return s.patchAs(nil, url, body)
}

func (s Server) patchAs(usr *ent.User, url string, body interface{}) (
	*http.Request, error,
) {
	return s.request(usr, http.MethodPut, url, body)
}

func (s Server) delete(url string) (*http.Request, error) {
	return s.deleteAs(nil, url)
}

func (s Server) deleteAs(usr *ent.User, url string) (*http.Request, error) {
	return s.request(usr, http.MethodDelete, url, nil)
}

func (s Server) request(
	usr *ent.User, method string, url string, body interface{},
) (req *http.Request, err error) {
	if nil == body {
		req, err = http.NewRequest(method, url, nil)
	} else {
		var jo []byte
		jo, err = json.Marshal(body)
		if err != nil {
			return
		}
		reader := io.NopCloser(strings.NewReader(string(jo)))
		if req, err = http.NewRequest(method, url, reader); err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
	}
	if err != nil || nil == usr {
		return
	}
	var at, rt string
	at, err = s.issueAccessToken(usr)
	if err != nil {
		return
	}
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
	rt, err = s.issueRefreshToken(usr)
	if err != nil {
		return
	}
	req.AddCookie(
		&http.Cookie{
			Name:     refreshTokenName,
			Value:    rt,
			Path:     api.RefreshTokenPath,
			Domain:   s.Domain(),
			MaxAge:   86400,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		},
	)
	return
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
	ids := make([]uint32, numFixtures)
	roles := make([]*ent.RoleCreate, numFixtures)
	users := make([]*ent.UserCreate, numFixtures)
	for i := range numFixtures {
		ids[i] = uint32(i + 1)
		roles[i] = client.Role.Create().SetName(fmt.Sprintf("role %d", i))
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

func getUserById(tb testing.TB, db *ent.Client, id uint64) *ent.User {
	u, err := db.User.Query().Where(user.IDEQ(id)).Only(context.Background())
	require.Nil(tb, err)
	return u
}

func pluckPermissionId(row *ent.Permission) uint32 { return row.ID }

func pluckRoleId(row *ent.Role) uint32 { return row.ID }

func uuu[T interface{}](
	tb testing.TB, data T, res *httptest.ResponseRecorder,
) T {
	var v T
	require.Nil(tb, json.Unmarshal([]byte(res.Body.String()), &v))
	return v
}

// this test is here for future change on auth & validation middleware, if it
// were to be made.
//
// In current setup, validation middleware is registered with `gin.use()`,
// which is a router group middleware. While auth middleware is registered
// using NewStrictHandler, which is an operation (route) middleware.
// `gin.combineHandlers()` puts all router group middleware before operation
// middleware. This means that the request will be validated before it is
// authenticated. This test is here to ensure that this behavior will not go
// un-noticed if this behavior were changed.
func Test_authMiddleware_runs_after_request_validation(t *testing.T) {
	svr, engine, _, res := setup(t, false)
	req, err := svr.post("/role/3/permissions", nil)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnprocessableEntity, res.Code)
}
