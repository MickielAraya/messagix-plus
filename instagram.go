package messagixplus

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/MickielAraya/messagix-plus/cookies"
	"github.com/MickielAraya/messagix-plus/crypto"
	"github.com/MickielAraya/messagix-plus/data/responses"
	"github.com/MickielAraya/messagix-plus/types"
	"github.com/MickielAraya/messagix-plus/utils"

	"github.com/google/go-querystring/query"
)

// specific methods for insta api, not socket related
type InstagramMethods struct {
	client *Client
}

func (ig *InstagramMethods) Login(identifier, password, totpSecret string) (cookies.Cookies, error) {
	ig.client.Account.Username = identifier
	ig.client.Account.Password = password
	ig.client.Account.TotpSecret = totpSecret

	ig.client.loadLoginPage()
	if err := ig.client.configs.SetupConfigs(); err != nil {
		return nil, err
	}

	h := ig.client.buildHeaders(false)
	h.Add("x-web-device-id", ig.client.cookies.GetValue("ig_did"))
	h.Add("sec-fetch-dest", "empty")
	h.Add("sec-fetch-mode", "cors")
	h.Add("sec-fetch-site", "same-origin")
	h.Add("x-requested-with", "XMLHttpRequest")
	h.Add("referer", ig.client.getEndpoint("login_page"))

	login_page_v1 := ig.client.getEndpoint("web_login_page_v1")
	_, _, err := ig.client.MakeRequest(login_page_v1, "GET", h, nil, types.NONE)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s for instagram login: %w", login_page_v1, err)
	}

	err = ig.client.sendCookieConsent("")
	if err != nil {
		return nil, err
	}

	web_shared_data_v1 := ig.client.getEndpoint("web_shared_data_v1")
	req, respBody, err := ig.client.MakeRequest(web_shared_data_v1, "GET", h, nil, types.NONE) // returns actual machineId you're supposed to use
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s for instagram login: %w", web_shared_data_v1, err)
	}

	cookies.UpdateFromResponse(ig.client.cookies, req.Header)

	err = json.Unmarshal(respBody, &ig.client.configs.browserConfigTable.XIGSharedData.ConfigData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal web_shared_data_v1 resp body into *XIGSharedData.ConfigData: %w", err)
	}

	encryptionConfig := ig.client.configs.browserConfigTable.XIGSharedData.ConfigData.Encryption
	pubKeyId, err := strconv.Atoi(encryptionConfig.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to convert keyId for instagram password encryption to int: %w", err)
	}

	encryptedPw, err := crypto.EncryptPassword(int(types.Instagram), pubKeyId, encryptionConfig.PublicKey, password)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt password for instagram: %w", err)
	}

	fmt.Println("WE HAVE JAZEOST? -> ", ig.client.configs.Jazoest)

	loginForm := &types.InstagramLoginPayload{
		EncPassword:          encryptedPw,
		OptIntoOneTap:        false,
		QueryParams:          `{"next":"https://www.instagram.com/accounts/onetap/?next=%2F&__coig_login=1"}`,
		TrustedDeviceRecords: "{}",
		Username:             identifier,
		Jazoest:              ig.client.configs.Jazoest,
	}

	form, err := query.Values(&loginForm)
	if err != nil {
		return nil, fmt.Errorf("failed to encode login form payload: %w", err)
	}

	web_login_ajax_v1 := ig.client.getEndpoint("web_login_ajax_v1")
	loginResp, loginBody, err := ig.client.Account.sendLoginRequest(form, web_login_ajax_v1)
	if err != nil {
		return nil, err
	}

	loginResult := ig.client.Account.processLogin(ig, loginResp, loginBody)
	if loginResult != nil {
		return nil, loginResult
	}

	return ig.client.cookies, nil
}

func (ig *InstagramMethods) TwoFactorLogin(username, identifier, totpSecret string) error {
	if identifier == "" || totpSecret == "" {
		return fmt.Errorf("missing identifier, or TOTP secret for Instagram two-factor login")
	}

	csrfToken := ig.client.cookies.GetValue("csrftoken")
	appID := ig.client.configs.browserConfigTable.CurrentUserInitialData.AppID
	igWWWClaim := "0"
	if instaCookies, ok := ig.client.cookies.(*cookies.InstagramCookies); ok && instaCookies.IgWWWClaim != "" {
		igWWWClaim = instaCookies.IgWWWClaim
	}

	totpCode, err := utils.GenerateTotpCode(totpSecret)
	if err != nil {
		return fmt.Errorf("failed to generate TOTP code: %w", err)
	}

	formBody := ""
	formOrder := []struct {
		k, v string
	}{
		{"identifier", identifier},
		{"isPrivacyPortalReq", "false"},
		{"queryParams", `{"next":"/"}`},
		{"trust_signal", "true"},
		{"username", username},
		{"verification_method", "3"},
		{"verificationCode", totpCode},
		{"jazoest", ig.client.configs.Jazoest},
	}

	for i, kv := range formOrder {
		if i > 0 {
			formBody += "&"
		}
		formBody += url.QueryEscape(kv.k) + "=" + url.QueryEscape(kv.v)
	}

	h := http.Header{}

	h.Set("Host", "www.instagram.com")
	h.Set("Cookie", cookies.CookiesToString(ig.client.cookies))
	h.Set("x-csrftoken", csrfToken)
	h.Set("accept-language", "en-US,en;q=0.6")
	h.Set("referer", "https://www.instagram.com/accounts/login/two_factor?next=%2F")
	h.Set("sec-ch-ua-platform-version", `"10.0.0"`)
	h.Set("sec-fetch-mode", "cors")
	h.Set("priority", "u=1, i")
	h.Set("sec-ch-ua-model", `""`)
	h.Set("sec-ch-ua-mobile", "?0")
	h.Set("x-ig-app-id", appID)
	h.Set("x-requested-with", "XMLHttpRequest")
	h.Set("accept", "*/*")
	h.Set("x-asbd-id", "359341")
	h.Set("x-ig-www-claim", igWWWClaim)
	h.Set("origin", "https://www.instagram.com")
	h.Set("sec-ch-ua-platform", `"Windows"`)
	h.Set("x-web-session-id", ig.client.configs.WebSessionId)
	h.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
	h.Set("sec-gpc", "1")
	h.Set("sec-fetch-site", "same-origin")
	h.Set("sec-fetch-dest", "empty")
	h.Set("sec-ch-ua-full-version-list", `"Brave";v="141.0.0.0", "Not?A_Brand";v="8.0.0.0", "Chromium";v="141.0.0.0"`)
	h.Set("sec-ch-ua", `"Brave";v="141", "Not?A_Brand";v="8", "Chromium";v="141"`)
	h.Set("x-instagram-ajax", "1028361656")

	apiURL := ig.client.getEndpoint("web_login_ajax_v1_two_factor")
	resp, respBody, err := ig.client.MakeRequest(apiURL, "POST", h, []byte(formBody), types.FORM)

	if err != nil {
		return fmt.Errorf("instagram 2FA request failed: %w", err)
	}

	cookies.UpdateFromResponse(ig.client.cookies, resp.Header)

	var loginResp types.InstagramLoginResponse
	if err := json.Unmarshal(respBody, &loginResp); err != nil {
		return fmt.Errorf("failed to decode instagram 2fa login JSON: %w", err)
	}

	if loginResp.Status == "fail" {
		if loginResp.Message != "" {
			return fmt.Errorf("2FA failed: %s", loginResp.Message)
		}
		return fmt.Errorf("2FA login failed, generic failure")
	}

	if !loginResp.Authenticated {
		return fmt.Errorf("2FA login failed: not authenticated")
	}

	return nil
}

func (ig *InstagramMethods) CaptchaLogin(username, identifier, totpSecret string) error {
	return nil
}

func (ig *InstagramMethods) FetchProfile(username string) (*responses.ProfileInfoResponse, error) {
	h := ig.client.buildHeaders(true)
	h.Add("x-requested-with", "XMLHttpRequest")
	h.Add("referer", ig.client.getEndpoint("base_url")+username+"/")
	reqUrl := ig.client.getEndpoint("web_profile_info") + "username=" + username

	resp, respBody, err := ig.client.MakeRequest(reqUrl, "GET", h, nil, types.NONE)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch the profile by username @%s: %e", username, err)
	}

	cookies.UpdateFromResponse(ig.client.cookies, resp.Header)

	var profileInfo *responses.ProfileInfoResponse
	err = json.Unmarshal(respBody, &profileInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response bytes into *responses.ProfileInfoResponse (statusCode=%d): %e", resp.StatusCode, err)
	}

	return profileInfo, nil
}

func (ig *InstagramMethods) FetchMedia(mediaId string) (*responses.FetchMediaResponse, error) {
	h := ig.client.buildHeaders(true)
	h.Add("x-requested-with", "XMLHttpRequest")
	h.Add("referer", ig.client.getEndpoint("base_url"))
	reqUrl := fmt.Sprintf(ig.client.getEndpoint("media_info"), mediaId)

	resp, respBody, err := ig.client.MakeRequest(reqUrl, "GET", h, nil, types.NONE)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch the media by id %s: %e", mediaId, err)
	}

	cookies.UpdateFromResponse(ig.client.cookies, resp.Header)

	var mediaInfo *responses.FetchMediaResponse
	err = json.Unmarshal(respBody, &mediaInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response bytes into *responses.FetchMediaResponse (statusCode=%d): %e", resp.StatusCode, err)
	}

	return mediaInfo, nil
}

func (ig *InstagramMethods) FetchReel(reelIds []string) (*responses.ReelInfoResponse, error) {
	h := ig.client.buildHeaders(true)
	h.Add("x-requested-with", "XMLHttpRequest")
	h.Add("referer", ig.client.getEndpoint("base_url"))
	query := url.Values{}
	for _, id := range reelIds {
		query.Add("reel_ids", id)
	}

	reqUrl := ig.client.getEndpoint("reels_media") + query.Encode()
	resp, respBody, err := ig.client.MakeRequest(reqUrl, "GET", h, nil, types.NONE)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch reels by ids %v: %e", reelIds, err)
	}

	cookies.UpdateFromResponse(ig.client.cookies, resp.Header)

	var reelInfo *responses.ReelInfoResponse
	err = json.Unmarshal(respBody, &reelInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response bytes into *responses.ReelInfoResponse (statusCode=%d): %e", resp.StatusCode, err)
	}

	return reelInfo, nil
}

// Hightlight IDs are different, they come in the format: "highlight:17913397615055292"
func (ig *InstagramMethods) FetchHighlights(highlightIds []string) (*responses.ReelInfoResponse, error) {
	return ig.FetchReel(highlightIds)
}
