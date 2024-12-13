package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/eidng8/go-utils"
	"github.com/oapi-codegen/runtime/types"

	"github.com/eidng8/go-attr-rbac/ent"
)

// CreateUser creates a user.
//
// Endpoint: POST /users
func (s Server) CreateUser(
	_ context.Context, request CreateUserRequestObject,
) (CreateUserResponseObject, error) {
	u, err := s.db.Transaction(
		context.Background(),
		func(qc context.Context, tx *ent.Tx) (interface{}, error) {
			return createUser(
				qc, tx.User.Create(), CreateUserJSONBody(*request.Body),
			)
		},
	)
	if err != nil {
		if ent.IsUniqueKeyError(err) {
			return CreateUser400JSONResponse{
				N400JSONResponse: N400JSONResponse{
					Code:   http.StatusBadRequest,
					Errors: &msgExists,
					Status: msgError,
				},
			}, nil
		} else if errors.Is(err, errPasswordToSimple) {
			var s interface{} = err.Error()
			return CreateUser400JSONResponse{
				N400JSONResponse: N400JSONResponse{
					Code:   http.StatusBadRequest,
					Errors: &s,
					Status: msgError,
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

func createUser(
	qc context.Context, tx *ent.UserCreate, data CreateUserJSONBody,
) (*ent.User, error) {
	create := tx.SetUsername(data.Username)
	if err := validatePassword(data.Password); err != nil {
		return nil, err
	}
	// TODO use a hasher predicate function config instead of hardcoding
	hash, err := utils.HashPassword(data.Password)
	if err != nil {
		return nil, err
	}
	create.SetPassword(hash)
	if data.Email != nil {
		create.SetEmail(string(*data.Email))
	}
	if data.Roles != nil && len(*data.Roles) > 0 {
		create.AddRoleIDs(*data.Roles...)
	}
	if data.Attr != nil {
		create.SetAttr(userAttrToMap(*data.Attr))
	}
	return create.Save(qc)
}

func validatePassword(password string) error {
	if !(numChecker.MatchString(password) &&
		lowercaseChecker.MatchString(password) &&
		uppercaseChecker.MatchString(password) &&
		specialChecker.MatchString(password)) {
		return errPasswordToSimple
	}
	return nil
}
