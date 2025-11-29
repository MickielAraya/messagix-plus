package tests_test

import (
	"log"
	"os"
	"testing"

	messagix "github.com/MickielAraya/messagix-plus"
	"github.com/MickielAraya/messagix-plus/cookies"
	"github.com/MickielAraya/messagix-plus/debug"
	"github.com/MickielAraya/messagix-plus/types"
)

func TestParseJS(t *testing.T) {
	session := cookies.InstagramCookies{}
	err := cookies.NewCookiesFromString(``, &session)
	if err != nil {
		log.Fatal(err)
	}

	cli, err := messagix.NewClient(types.Instagram, &session, "", debug.NewLogger())
	if err != nil {
		log.Fatal(err)
	}
	parser := &messagix.ModuleParser{}
	testData, _ := os.ReadFile("test_files/res.html")
	parser.SetTestData(testData)
	parser.SetClientInstance(cli)
	parser.Load("https://www.instagram.com/direct/inbox/")
	//parser.Load("https://www.instagram.com/accounts/login/")
}
