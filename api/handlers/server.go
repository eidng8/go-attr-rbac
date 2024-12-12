package handlers

import (
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/eidng8/go-utils"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	jsoniter "github.com/json-iterator/go"
	gmw "github.com/oapi-codegen/gin-middleware"

	"github.com/eidng8/go-attr-rbac/api"
	"github.com/eidng8/go-attr-rbac/ent"
	_ "github.com/eidng8/go-attr-rbac/ent/runtime"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type Server struct {
	db *ent.Client
	// base URL for the URL generation
	baseUrl string
	// private key for JWT token generation
	secret []byte
	// number of rows to return in hint requests
	hintSize int
	// list of public operations
	publicOperations []string
	// password hash parameters, for `argon2id`
	passwordHashParams utils.PasswordHashParams
}

func NewEngine(entClient *ent.Client) (*Server, *gin.Engine, error) {
	if nil != entClient {
		params, err := utils.DefaultPasswordHashParams()
		utils.PanicIfError(err)
		dbSetup(entClient, *params)
		// entClient = entClient.Debug()
	}
	gin.SetMode(utils.GetEnvWithDefault(gin.EnvGinMode, gin.ReleaseMode))
	engine := gin.Default()
	newSwaggerServer(engine)
	server := newApiServer(entClient)
	newApiHandler(server, engine)
	return server, engine, nil
}

func newApiServer(db *ent.Client) *Server {
	secret, err := getSecret()
	utils.PanicIfError(err)
	return &Server{
		db:               db,
		baseUrl:          os.Getenv(api.BaseUrlName),
		secret:           secret,
		hintSize:         getHintSize(5),
		publicOperations: getPublicOperations(),
	}
}

func newApiHandler(server *Server, engine *gin.Engine) ServerInterface {
	handler := NewStrictHandler(
		server, []StrictMiddlewareFunc{
			server.authMiddleware(),
		},
	)
	RegisterHandlersWithOptions(
		engine, handler, GinServerOptions{
			// BaseURL: "/api",
			ErrorHandler: func(ctx *gin.Context, err error, code int) {
				// Error handler is called directly by ServerInterfaceWrapper
				// methods (such as ServerInterfaceWrapper.ListPermission).
				// It doesn't get into middleware or any other lines of process.
				if http.StatusBadRequest == code {
					code = http.StatusUnprocessableEntity
				}
				ctx.JSON(code, gin.H{"error": err.Error()})
			},
		},
	)
	return handler
}

func newSwaggerServer(engine *gin.Engine) *openapi3.T {
	swagger, err := GetSwagger()
	utils.PanicIfError(err)
	swagger.Servers = nil
	engine.Use(
		gmw.OapiRequestValidatorWithOptions(
			swagger, &gmw.Options{
				ErrorHandler: func(
					c *gin.Context, message string, statusCode int,
				) {
					if http.StatusBadRequest == statusCode {
						message, _ = strings.CutPrefix(
							message, "error in openapi3filter.",
						)
						c.AbortWithStatusJSON(
							http.StatusUnprocessableEntity,
							gin.H{"error": message},
						)
					} else {
						c.AbortWithStatusJSON(
							statusCode, gin.H{"error": message},
						)
					}
				},
			},
		),
	)
	return swagger
}

// Domain returns the domain name of base URL.
func (s Server) Domain() string {
	u, err := url.Parse(s.baseUrl)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// getSecret returns the secret key for the JWT token generation.
// For use by `jwt.Parse()`.
func (s Server) getSecret(_ *jwt.Token) (interface{}, error) {
	return s.secret, nil
}

func (s Server) setCookie(
	gc *gin.Context, name, value, path string, maxAge int,
) {
	gc.SetCookie(name, value, maxAge, path, s.Domain(), true, true)
}

// Sets the access and refresh token cookies.
func (s Server) setToken(gc *gin.Context, accessToken, refreshToken string) {
	gc.SetSameSite(http.SameSiteStrictMode)
	s.setCookie(gc, accessTokenName, accessToken, "/", 3600)
	s.setCookie(
		gc, refreshTokenName, refreshToken, api.RefreshTokenPath, 7*24*3600,
	)
}

// Returns the jwtToken from the gin.Context.
func (s Server) getToken(gc *gin.Context) (*jwtToken, error) {
	token, ok := gc.Value(accessTokenName).(*jwtToken)
	if !ok {
		return nil, errInvalidContext
	}
	return token, nil
}

var _ StrictServerInterface = (*Server)(nil)
