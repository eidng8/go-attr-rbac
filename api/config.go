package api

import (
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/eidng8/go-utils"
)

func getHintSize(defaultValue int64) int {
	hintSize, err := strconv.ParseInt(
		utils.GetEnvWithDefaultNE(HintSizeName, "5"), 10, 32,
	)
	utils.PanicIfError(err)
	if hintSize < 1 {
		hintSize = defaultValue
	}
	return int(hintSize)
}

// Retrieves the list of public operations from the environment variable,
// separated by comma, removes any whitespace-only strings.
// Adds `auth:login` and `auth:refreshAccessToken` to the list if not present.
// Operations are case-sensitive.
func getPublicOperations() []string {
	ws := regexp.MustCompile(`^\s+$`)
	ops := slices.DeleteFunc(
		strings.Split(os.Getenv(PublicOpsName), ","),
		func(s string) bool { return ws.MatchString(s) },
	)
	if !slices.Contains(ops, OperationLogin) {
		ops = append(ops, OperationLogin)
	}
	if !slices.Contains(ops, OperationRefreshToken) {
		ops = append(ops, OperationRefreshToken)
	}
	return ops
}

// Retrieves the secret key (base64 string) from environment variable.
func getSecret() ([]byte, error) {
	secret := os.Getenv(PrivateKeyName)
	if "" == secret {
		return nil, fmt.Errorf(
			"%s environment variable is not set", PrivateKeyName,
		)
	}
	key, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}
	return key, nil
}
