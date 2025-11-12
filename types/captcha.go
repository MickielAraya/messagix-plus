package types

type InstagramCaptchaResponse struct {
	ChallengeType string   `json:"challengeType"`
	Errors        []string `json:"errors"`
	Experiments   struct{} `json:"experiments"`
	ExtraData     any      `json:"extraData"`
	Fields        struct {
		GRecaptchaResponse      string `json:"g-recaptcha-response"`
		DisableNumDaysRemaining int    `json:"disable_num_days_remaining"`
		CodeWhitelisted         bool   `json:"code_whitelisted"`
		UserID                  string `json:"user_id"`
		ActaPropagation         bool   `json:"acta_propagation"`
		RecaptchaBypass         bool   `json:"recaptcha_bypass"`
		ChallengeName           string `json:"challenge_name"`
	} `json:"fields"`
	Navigation struct {
		Forward string `json:"forward"`
		Replay  string `json:"replay"`
		Dismiss string `json:"dismiss"`
	} `json:"navigation"`
	PrivacyPolicyUrl string `json:"privacyPolicyUrl"`
	Type             string `json:"type"`
	ChallengeContext string `json:"challenge_context"`
	Status           string `json:"status"`
}

type InstagramCaptchaActionResponse struct {
	Location string `json:"location"`
	Type     string `json:"type"`
	Status   string `json:"status"`
}
