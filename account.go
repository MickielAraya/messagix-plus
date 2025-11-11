package messagixplus

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/MickielAraya/messagix-plus/cookies"
	"github.com/MickielAraya/messagix-plus/socket"
	"github.com/MickielAraya/messagix-plus/table"
	"github.com/MickielAraya/messagix-plus/types"

	"github.com/google/uuid"
)

type Account struct {
	client     *Client
	Username   string
	Password   string
	TotpSecret string
}

func (a *Account) processLogin(ig *InstagramMethods, resp *http.Response, respBody []byte) error {
	statusCode := resp.StatusCode
	var err error
	switch a.client.platform {
	case types.Instagram:
		var loginResp types.InstagramLoginResponse
		err = json.Unmarshal(respBody, &loginResp)
		if err != nil {
			return fmt.Errorf("failed to unmarshal instagram login response to *types.InstagramLoginResponse (statusCode=%d): %w", statusCode, err)
		}

		if loginResp.Status == "fail" {
			if loginResp.TwoFactorRequired {
				if loginResp.TwoFactorInfo == nil || !loginResp.TwoFactorInfo.TotpTwoFactorOn {
					return fmt.Errorf("two factor required but TOTP is not enabled for this account")
				}

				err = ig.TwoFactorLogin(a.Username, loginResp.TwoFactorInfo.TwoFactorIdentifier, a.TotpSecret)
				if err == nil {
					break
				}
			}

			if loginResp.Message == "checkpoint_required" {
				err = fmt.Errorf("failed to process login due to captcha (checkpointUrl=%s, message=%s, statusText=%s, statusCode=%d)", loginResp.CheckpointUrl, loginResp.Message, loginResp.Status, statusCode)
				if err != nil {
					return err
				}

				return fmt.Errorf("failed to process login due to captcha (checkpointUrl=%s, message=%s, statusText=%s, statusCode=%d)", loginResp.CheckpointUrl, loginResp.Message, loginResp.Status, statusCode)
			}

			err = fmt.Errorf("failed to process login request (message=%s, statusText=%s, statusCode=%d)", loginResp.Message, loginResp.Status, statusCode)
		} else if !loginResp.Authenticated {
			err = fmt.Errorf("failed to login, invalid password (userExists=%t, statusText=%s, statusCode=%d)", loginResp.User, loginResp.Status, statusCode)
		}

		a.client.cookies.(*cookies.InstagramCookies).IgWWWClaim = resp.Header.Get("x-ig-set-www-claim")
	}

	if err == nil {
		cookies.UpdateFromResponse(a.client.cookies, resp.Header)
	}

	return err
}

func (a *Account) GetContacts(limit int64) ([]table.LSVerifyContactRowExists, error) {
	tskm := a.client.NewTaskManager()
	tskm.AddNewTask(&socket.GetContactsTask{Limit: limit})

	payload, err := tskm.FinalizePayload()
	if err != nil {
		log.Fatal(err)
	}

	packetId, err := a.client.socket.makeLSRequest(payload, 3)
	if err != nil {
		log.Fatal(err)
	}

	resp := a.client.socket.responseHandler.waitForPubResponseDetails(packetId)
	if resp == nil {
		return nil, fmt.Errorf("failed to receive response from socket while trying to fetch contacts. packetId: %d", packetId)
	}

	return resp.Table.LSVerifyContactRowExists, nil
}

func (a *Account) GetContactsFull(contactIds []int64) ([]table.LSDeleteThenInsertContact, error) {
	tskm := a.client.NewTaskManager()
	for _, id := range contactIds {
		tskm.AddNewTask(&socket.GetContactsFullTask{
			ContactId: id,
		})
	}

	payload, err := tskm.FinalizePayload()
	if err != nil {
		log.Fatal(err)
	}

	packetId, err := a.client.socket.makeLSRequest(payload, 3)
	if err != nil {
		log.Fatal(err)
	}

	resp := a.client.socket.responseHandler.waitForPubResponseDetails(packetId)
	if resp == nil {
		return nil, fmt.Errorf("failed to receive response from socket while trying to fetch full contact information. packetId: %d", packetId)
	}

	return resp.Table.LSDeleteThenInsertContact, nil
}

func (a *Account) ReportAppState(state table.AppState) error {
	tskm := a.client.NewTaskManager()
	tskm.AddNewTask(&socket.ReportAppStateTask{AppState: state, RequestId: uuid.NewString()})

	payload, err := tskm.FinalizePayload()
	if err != nil {
		log.Fatal(err)
	}

	packetId, err := a.client.socket.makeLSRequest(payload, 3)
	if err != nil {
		log.Fatal(err)
	}

	resp := a.client.socket.responseHandler.waitForPubResponseDetails(packetId)
	if resp == nil {
		return fmt.Errorf("failed to receive response from socket while trying to report app state. packetId: %d", packetId)
	}

	return nil
}
