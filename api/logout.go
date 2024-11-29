package api

import (
    "context"
    "net/http"

    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v5"

    "github.com/eidng8/go-attr-rbac/ent"
    "github.com/eidng8/go-attr-rbac/ent/accesstoken"
)

func (s Server) Logout(
    ctx context.Context, _ LogoutRequestObject,
) (LogoutResponseObject, error) {
    err := rat(s, ctx)
    if err != nil {
        log.Debugf("failed to revoke access token: %v", err)
        return Logout401Response{}, err
    }
    return Logout204Response{}, nil
}

func (s Server) RevokeAccessToken(
    ctx context.Context, _ RevokeAccessTokenRequestObject,
) (RevokeAccessTokenResponseObject, error) {
    err := rat(s, ctx)
    if err != nil {
        log.Debugf("failed to revoke access token: %v", err)
        return RefreshAccessToken401Response{}, nil
    }
    return RevokeAccessToken204Response{}, nil
}

func rat(s Server, ctx context.Context) error {
    gc, ok := ctx.(*gin.Context)
    if !ok {
        return ErrInvalidContext
    }
    at, err := s.verifyAccessToken(gc)
    if err != nil {
        return err
    }
    rt, err := s.getToken(gc, RefreshTokenName)
    if err != nil {
        return err
    }
    if err = revokeAccessToken(s, at, rt); err != nil {
        return err
    }
    gc.SetSameSite(http.SameSiteStrictMode)
    s.setCookie(gc, AccessTokenName, "", "/", -1)
    s.setCookie(gc, RefreshTokenName, "", "/access-token", -1)
    return nil
}

func revokeAccessToken(s Server, at, rt *jwt.Token) error {
    // check if the token jti was revoked
    atid, err := getJtiBinary(at)
    if err != nil {
        log.Debugf("invalid acess token id %#v", at)
        return ErrInvalidToken
    }
    rtid, err := getJtiBinary(rt)
    if err != nil {
        log.Debugf("invalid refresh token id %#v", rt)
        return ErrInvalidToken
    }
    exist, err := s.db.AccessToken.Query().Where(
        accesstoken.Or(
            accesstoken.AccessTokenEQ(atid), accesstoken.RefreshTokenEQ(rtid),
        ),
    ).Exist(context.Background())
    if err != nil {
        log.Debugf("token query error: %v", err)
        return err
    }
    if exist {
        log.Debugf("access token or refresh token has been revoked")
        return ErrInvalidToken
    }

    // get user id from token subject
    u, err := getUserBySubject(s, at)
    if err != nil {
        return ErrInvalidToken
    }

    // add the token to the revoked list
    _, err = s.db.Transaction(
        context.Background(),
        func(ctx context.Context, tx *ent.Tx) (interface{}, error) {
            _, err := tx.AccessToken.Create().SetUserID(u.ID).
                SetAccessToken(atid).SetRefreshToken(rtid).
                Save(ctx)
            if err != nil {
                return nil, err
            }
            return nil, nil
        },
    )
    if err != nil {
        log.Debugf("save token error: %s", err)
        return err
    }
    return nil
}
