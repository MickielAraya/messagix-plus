package tests_test

import (
	"testing"

	messagixplus "github.com/MickielAraya/messagix-plus"
	cookies "github.com/MickielAraya/messagix-plus/cookies"
	"github.com/MickielAraya/messagix-plus/debug"
	"github.com/MickielAraya/messagix-plus/types"
)

func TestSendMessage(t *testing.T) {
	threadId := int64(0)

	session := cookies.InstagramCookies{}
	err := cookies.NewCookiesFromString(
		``,
		&session,
	)
	if err != nil {
		t.Fatalf("failed to create instagram cookies: %v", err)
	}

	cli, err := messagixplus.NewClient(types.Instagram, &session, debug.NewLogger(), "")
	if err != nil {
		t.Fatalf("failed to create messagix client: %v", err)
	}

	err = cli.Connect()
	if err != nil {
		t.Fatalf("failed to connect to messagix client: %v", err)
	}

	messageBuilder := cli.Threads.NewMessageBuilder(threadId)
	messageBuilder.SetText("Hello, world!")

	_, err = messageBuilder.Execute()
	if err != nil {
		t.Fatalf("failed to execute message builder: %v", err)
	}
}
