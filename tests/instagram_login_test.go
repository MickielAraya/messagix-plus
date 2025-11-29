package tests_test

import (
	"fmt"
	"testing"

	messagixplus "github.com/MickielAraya/messagix-plus"
	cookies "github.com/MickielAraya/messagix-plus/cookies"
	debug "github.com/MickielAraya/messagix-plus/debug"
	types "github.com/MickielAraya/messagix-plus/types"
)

func TestLogin(t *testing.T) {
	session := cookies.InstagramCookies{}
	err := cookies.NewCookiesFromString(``, &session)
	if err != nil {
		t.Fatalf("failed to create instagram cookies: %v", err)
	}

	// Fill in your proxy
	proxy := ""

	cli, err := messagixplus.NewClient(types.Instagram, &session, proxy, debug.NewLogger())
	if err != nil {
		t.Fatalf("failed to create messagix client: %v", err)
	}

	// Fill in your credentials
	username := ""
	password := ""
	totp := ""
	capSolverKey := ""

	cookies, err := cli.Instagram.Login(username, password, totp, 0, capSolverKey)
	if err != nil {
		t.Fatalf("failed to login: %v", err)
	}

	fmt.Println(cookies)
}
