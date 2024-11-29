package api

import (
    "context"
    "errors"
    "fmt"
    "strconv"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"

    "github.com/eidng8/go-attr-rbac/ent"
    "github.com/eidng8/go-attr-rbac/ent/accesstoken"
    "github.com/eidng8/go-attr-rbac/ent/user"
)

const (
    AccessTokenName  = "access_token"
    RefreshTokenName = "refresh_token"
)

var (
    ErrInvalidToken = errors.New("invalid_token")
    ErrEmptyToken   = errors.New("empty_token")
)

type TokenClaims struct {
    jwt.RegisteredClaims
}

type AccessTokenClaims struct {
    jwt.RegisteredClaims
    Roles *[]string `json:"roles,omitempty"`
}

func issueAccessToken(s Server, user *ent.User) (string, error) {
    roles, err := user.QueryRoles().Select("name").All(context.Background())
    if err != nil {
        return "", err
    }
    r := make([]string, len(roles))
    for i, role := range roles {
        r[i] = role.Name
    }
    return issueJwtToken(s, user, time.Hour, &r)
}

func issueRefreshToken(s Server, user *ent.User) (string, error) {
    return issueJwtToken(s, user, 7*24*time.Hour, nil)
}

// issueAccessToken issues an access token for the user.
// Doesn't access database.
func issueJwtToken(
    s Server, user *ent.User, ttl time.Duration, roles *[]string,
) (string, error) {
    uid, err := uuid.NewV7()
    if err != nil {
        return "", err
    }
    claims := jwt.NewWithClaims(
        jwt.SigningMethodHS256, AccessTokenClaims{
            Roles: roles,
            RegisteredClaims: jwt.RegisteredClaims{
                Audience:  []string{s.Domain()}, // TODO allow customize?
                Issuer:    s.Domain(),           // TODO allow customize?
                Subject:   fmt.Sprintf("%d", user.ID),
                ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(ttl)},
                ID:        uid.String(),
            },
        },
    )
    claims.Method = jwt.SigningMethodHS256
    token, err := claims.SignedString(s.secret)
    if err != nil {
        return "", err
    }
    return token, nil
}

// getJti checks the token id validity and returns it. Doesn't access database.
func getJti(token *jwt.Token) (uuid.UUID, error) {
    claims, ok := token.Claims.(*TokenClaims)
    if !ok {
        return uuid.Nil, ErrInvalidToken
    }
    id, err := uuid.Parse(claims.ID)
    if err != nil {
        return uuid.Nil, err
    }
    return id, nil
}

// getJtiBinary checks the token id validity and returns it as binary.
// Doesn't access database.
func getJtiBinary(token *jwt.Token) ([]byte, error) {
    id, err := getJti(token)
    if err != nil {
        return nil, err
    }
    bytes, err := id.MarshalBinary()
    if err != nil {
        return nil, err
    }
    return bytes, nil
}

// getUserBySubject checks the subject validity and returns the user
// id. Accesses database. Logs errors.
func getUserBySubject(s Server, token *jwt.Token) (
    *ent.User, error,
) {
    subject, err := token.Claims.GetSubject()
    if err != nil {
        log.Debugf("failed to get subject from token: %v", err)
        return nil, ErrInvalidToken
    }
    id, err := strconv.ParseUint(subject, 10, 64)
    if err != nil {
        log.Debugf("invalid subject %s", subject)
        return nil, ErrInvalidToken
    }
    u, err := s.db.User.Query().Where(user.IDEQ(id)).
        First(context.Background())
    if err != nil {
        log.Debugf("query user error: %s", err)
        return nil, ErrInvalidToken
    }
    if nil == u {
        log.Debugf("user not found %d", id)
        return nil, ErrInvalidToken
    }
    return u, nil
}

// parseToken parses the token string and returns the token.
// Doesn't access database.
func parseToken(s Server, token string) (*jwt.Token, error) {
    t, err := jwt.Parse(
        token, s.getSecret,
        jwt.WithAudience(s.Domain()),
        jwt.WithExpirationRequired(),
        jwt.WithIssuer(s.Domain()),
        jwt.WithJSONNumber(),
        jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
    )
    if err != nil {
        return nil, err
    }
    if !t.Valid {
        return nil, ErrInvalidToken
    }
    return t, nil
}

// checkAccessToken checks the access token validity and returns it.
// Accesses database. Logs errors.
func checkAccessToken(s Server, token *jwt.Token) error {
    return checkToken(
        s, token, func(jti []byte) bool {
            exist, err := s.db.AccessToken.Query().
                Where(accesstoken.AccessTokenEQ(jti)).
                Exist(context.Background())
            if err != nil {
                log.Debugf("access token jti query error: %v", err)
                return false
            }
            return exist
        },
    )
}

// checkRefreshToken checks the refresh token validity and returns it.
// Accesses database. Logs errors.
func checkRefreshToken(s Server, token *jwt.Token) error {
    return checkToken(
        s, token, func(jti []byte) bool {
            exist, err := s.db.AccessToken.Query().
                Where(accesstoken.RefreshTokenEQ(jti)).
                Exist(context.Background())
            if err != nil {
                log.Debugf("refresh token jti query error: %v", err)
                return false
            }
            return exist
        },
    )
}

// checkToken checks the token validity. Accesses database. Logs errors.
func checkToken(s Server, token *jwt.Token, exists func([]byte) bool) error {
    if _, err := getUserBySubject(s, token); err != nil {
        return ErrInvalidToken
    }
    jti, err := getJtiBinary(token)
    if err != nil {
        log.Debugf("invalid jti: %v", err)
        return ErrInvalidToken
    }
    if exists(jti) {
        log.Debugf("token has been revoked")
        return ErrInvalidToken
    }
    return nil
}

// isTokenExpired checks if the token is expired. Doesn't access database.
// Logs errors.
func isTokenExpired(token *jwt.Token) error {
    exp, err := token.Claims.GetExpirationTime()
    if err != nil {
        log.Debugf("invalid expiration %v", err)
        return ErrInvalidToken
    }
    if exp.IsZero() {
        log.Debugf("zero expiration")
        return ErrInvalidToken
    }
    if exp.Before(time.Now()) {
        log.Debugf(jwt.ErrTokenExpired.Error())
        return jwt.ErrTokenExpired
    }
    return nil
}
