package handlers

import (
	"context"
	"errors"
	"net/http"
	"regexp"

	"github.com/eidng8/go-utils"
	"github.com/oapi-codegen/runtime/types"

	"github.com/eidng8/go-attr-rbac/ent"
)

var (
	numChecker       = regexp.MustCompile(`[0-9]+`)
	uppercaseChecker = regexp.MustCompile(`[A-Z]+`)
	lowercaseChecker = regexp.MustCompile(`[a-z]+`)
	specialChecker   = regexp.MustCompile(`[#?!@$%^&*-_]+`)

	errPasswordToSimple = errors.New(
		"password must contain at least 8 characters, " +
			"including uppercase, lowercase, number, and special characters" +
			" (#?!@$%^&*-_)",
	)
)

// CreateUser creates a user.
//
// Endpoint: POST /users
func (s Server) CreateUser(
	ctx context.Context, request CreateUserRequestObject,
) (CreateUserResponseObject, error) {
	u, err := s.db.Transaction(
		context.Background(),
		func(qc context.Context, tx *ent.Tx) (interface{}, error) {
			create := tx.User.Create().SetUsername(request.Body.Username)
			if !(numChecker.MatchString(request.Body.Password) &&
				lowercaseChecker.MatchString(request.Body.Password) &&
				uppercaseChecker.MatchString(request.Body.Password) &&
				specialChecker.MatchString(request.Body.Password)) {
				return nil, errPasswordToSimple
			}
			hash, err := utils.HashPassword(request.Body.Password)
			if err != nil {
				return nil, err
			}
			create.SetPassword(hash)
			if request.Body.Email != nil {
				create.SetEmail(string(*request.Body.Email))
			}
			if request.Body.Roles != nil && len(*request.Body.Roles) > 0 {
				roles, err := utils.SliceMapFunc(
					*request.Body.Roles, func(r uint32) (*ent.Role, error) {
						return &ent.Role{ID: r}, nil
					},
				)
				if err != nil {
					return nil, err
				}
				create.AddRoles(roles...)
			}
			if request.Body.Attr != nil {
				attr := make(map[string]interface{}, 2)
				attr["dept"] = request.Body.Attr.Dept
				attr["level"] = request.Body.Attr.Level
				create.SetAttr(&attr)
			}
			return create.Save(ctx)
		},
	)
	if err != nil {
		if ent.IsUniqueKeyError(err) {
			var s interface{} = "user already exists"
			return CreateUser400JSONResponse{
				N400JSONResponse: N400JSONResponse{
					Code:   http.StatusBadRequest,
					Errors: &s,
					Status: "error",
				},
			}, nil
		} else if errors.Is(err, errPasswordToSimple) {
			var s interface{} = err.Error()
			return CreateUser400JSONResponse{
				N400JSONResponse: N400JSONResponse{
					Code:   http.StatusBadRequest,
					Errors: &s,
					Status: "error",
				},
			}, nil
		}
		return nil, err
	}
	user := u.(*ent.User)
	res := CreateUser201JSONResponse{
		Id:        user.ID,
		Username:  user.Username,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
	if nil != user.Email && "" != *user.Email {
		email := types.Email(*user.Email)
		res.Email = &email
	}
	return res, nil
}
