package api

import (
	"github.com/eidng8/go-utils"
)

const (
	BaseUrlName             = "BASE_URL"
	PrivateKeyName          = "PRIVATE_KEY"
	HintSizeName            = "HINT_SIZE"
	PublicOpsName           = "PUBLIC_OPERATIONS"
	RefreshTokenPath        = "/access-token/refresh"
	PasswordHashTimesName   = "PASSWORD_HASH_TIMES"
	PasswordHashMemoryName  = "PASSWORD_HASH_MEMORY"
	PasswordHashThreadsName = "PASSWORD_HASH_THREADS"
	PasswordHashKeyLenName  = "PASSWORD_HASH_KEY_LENGTH"
)

var (
	Log = utils.NewLogger()
)
