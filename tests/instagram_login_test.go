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

	// Fill in proxy of your choice or MITM
	cli, err := messagixplus.NewClient(types.Instagram, &session, debug.NewLogger(), "")
	if err != nil {
		t.Fatalf("failed to create messagix client: %v", err)
	}

	// Fill in your credentials
	cookies, err := cli.Instagram.Login("", "", "", 0, "")
	if err != nil {
		t.Fatalf("failed to login: %v", err)
	}

	fmt.Println(cookies)
}
