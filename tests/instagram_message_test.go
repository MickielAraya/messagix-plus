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
		`ps_n=1;datr=94oSaacMyFB3MtGGtTwWEiIY;ig_nrcb=1;ds_user_id=3028794058;csrftoken=Sr7JQcgXwysCIlRRx2fYwQvpqHehVy4e;ig_did=72FBFEF8-BA6E-4B67-8CC0-72C546D2FAE2;ps_l=1;wd=1705x872;mid=aRKK9wALAAFCfFUI_YLvSvHBxLej;sessionid=3028794058%3A5rqO6J8rHGZDzz%3A21%3AAYiKU1k5R87slzo9kagnc-v-Z1ixho19u37RYCb2MA;dpr=1.100000023841858;rur="NHA\0543028794058\0541794404312:01feb4c526c260e48060afca8bf2799811aca5c33cbc1ef24b0d6a46c93f4831f9fad7ad"`,
		&session,
	)
	if err != nil {
		t.Fatalf("failed to create instagram cookies: %v", err)
	}

	cli, err := messagixplus.NewClient(types.Instagram, &session, debug.NewLogger(), "http://127.0.0.1:8888")
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
