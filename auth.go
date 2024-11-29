package main

import (
	"net/http"
)

type Authenticator[T interface{}] interface {
	Authenticate() (bool, error)
	GetUser() *T
}

type DefaultAuthenticator struct {
	request *http.Request
	user    *UsernamePasswordProvider
}

func GetDefaultAuthenticator(request *http.Request) Authenticator[UsernamePasswordProvider] {
	return &DefaultAuthenticator{
		request: request,
		user:    GetDefaultUserProvider(),
	}
}

func (a *DefaultAuthenticator) Authenticate() (bool, error) {
	if nil == a.user {
		a.user = GetDefaultUserProvider()
	}
	user, err := a.user.GetDetail(a.request.Body)
	if err != nil {
		return false, err
	}
	return nil != user, nil
}

func (a *DefaultAuthenticator) GetUser() *UsernamePasswordProvider {
	return a.user
}
