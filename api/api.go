package api

import (
	"github.com/eidng8/go-utils"
)

const (
	BaseUrlName    = "BASE_URL"
	PrivateKeyName = "PRIVATE_KEY"
	HintSizeName   = "HINT_SIZE"
	PublicOpsName  = "PUBLIC_OPERATIONS"

	OperationLogin        = "auth:Login"
	OperationRefreshToken = "auth:RefreshAccessToken"
	RefreshTokenPath      = "/access-token/refresh"
)

var (
	Log = utils.NewLogger()

	ResponseMessageCredentialNotFound interface{} = "invalid credentials"

	ResponseMessageCredentialsInvalid interface{} = "invalid credentials"
)
