package main

import (
	"context"
	"io"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/eidng8/go-db"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/user"
)

type UsernamePassword struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type EmailPassword struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Token struct {
	Token string `json:"token"`
}

type UserProvider interface {
	GetDetail(credentials io.Reader) (*ent.User, error)
	GetRoles() ([]string, error)
	GetClaims() (*map[string]string, error)
}

type UsernamePasswordProvider struct {
	user *ent.User
}

func (p UsernamePasswordProvider) GetDetail(credentials io.Reader) (
	*ent.User, error,
) {
	if nil != p.user {
		return p.user, nil
	}
	var cred UsernamePassword
	err := json.NewDecoder(credentials).Decode(&cred)
	if err != nil {
		return nil, err
	}
	p.user, err = ent.NewClient(ent.Driver(entsql.OpenDB(db.ConnectX()))).
		User.Query().Where(user.Username(cred.Username)).
		First(context.Background())
	if err != nil {
		return nil, err
	}
	if nil == p.user {
		return nil, nil
	}
	return p.user, nil
}

func (p UsernamePasswordProvider) GetRoles() ([]string, error) {
	// TODO implement me
	panic("implement me")
}

func (p UsernamePasswordProvider) GetClaims() (*map[string]string, error) {
	// TODO implement me
	panic("implement me")
}

func GetDefaultUserProvider() *UsernamePasswordProvider {
	return &UsernamePasswordProvider{}
}
