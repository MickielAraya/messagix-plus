package utils

import (
	"regexp"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

func GenerateTotpCode(secret string) (string, error) {
	secret = strings.ReplaceAll(secret, " ", "")
	secret = strings.TrimSpace(secret)
	secretTime := time.Now()
	var code string

	secret = regexp.MustCompile(`\s+`).ReplaceAllString(secret, ``)

	code, err := totp.GenerateCode(secret, secretTime)
	if err != nil {
		return code, err
	}

	return code, nil
}
