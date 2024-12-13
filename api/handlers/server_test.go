package handlers

import (
	"encoding/base64"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/eidng8/go-utils"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/api"
	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/enttest"
)

const numFixtures = 10

var (
	testdb    *ent.Client
	startTime = time.Now()
)

func setupTestEnv(tb testing.TB) {
	api.Log.Debug = true
	require.Nil(tb, os.Setenv(api.BaseUrlName, "http://localhost"))
	require.Nil(tb, os.Setenv(api.PrivateKeyName, randomSecret(32)))
	require.Nil(tb, os.Setenv(api.PublicOpsName, "ping"))
}

func useEmptyDb(tb testing.TB) *ent.Client {
	db, err := ent.Open("sqlite3", ":memory:?_fk=1")
	require.Nil(tb, err)
	tb.Cleanup(func() { require.Nil(tb, db.Close()) })
	return db
}
func setupTestCaseWithEmptyDb(tb testing.TB) (
	*Server, *gin.Engine, *ent.Client, *httptest.ResponseRecorder,
) {
	setupTestEnv(tb)
	db := enttest.Open(tb, "sqlite3", ":memory:?_fk=1")
	tb.Cleanup(func() { require.Nil(tb, db.Close()) })
	server, engine, err := NewEngine(nil)
	require.Nil(tb, err)
	startTime = time.Now()
	return server, engine, testdb, httptest.NewRecorder()
}

// Creates a new server, engine, and client for testing.
// If there were no previously connected database, this function will create a
// new database for testing populated with fixture data. If `refresh` is true,
// the database will be closed after the test; otherwise the database will
// be left open for further testing.
func setupTestCase(tb testing.TB, refresh bool) (
	*Server, *gin.Engine, *ent.Client, *httptest.ResponseRecorder,
) {
	nrd := nil == testdb
	setupTestEnv(tb)
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
	require.Nil(tb, err)
	if nrd {
		fixture(tb, testdb)
	}
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
	return s.request(usr, http.MethodPatch, url, body)
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
			Path:     api.AccessTokenPath,
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

func randomSecret(width int) string {
	bytes := make([]byte, width)
	for i := range width {
		bytes[i] = byte(rand.UintN(256))
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

func unmarshalResponse[T interface{}](
	tb testing.TB, data T, res *httptest.ResponseRecorder,
) T {
	var v T
	require.Nil(tb, json.Unmarshal(res.Body.Bytes(), &v))
	return v
}

func getTokensFromSetCookieHeaders(
	tb testing.TB, res *httptest.ResponseRecorder,
) (accessToken, refreshToken *http.Cookie) {
	cookies, err := utils.SliceMapFunc(
		res.Header().Values("Set-Cookie"),
		func(c string) (*http.Cookie, error) { return http.ParseSetCookie(c) },
	)
	require.Nil(tb, err)
	for _, c := range cookies {
		switch c.Name {
		case accessTokenName:
			accessToken = c
		case refreshTokenName:
			refreshToken = c
		}
	}
	return
}

func Test_Domain_returns_empty_string_if_error(t *testing.T) {
	svr := Server{baseUrl: "\x01"}
	require.Empty(t, svr.Domain())
}
