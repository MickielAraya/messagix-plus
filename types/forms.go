package types

type LoginForm struct {
	Jazoest              string `url:"jazoest" name:"jazoest"`
	Lsd                  string `url:"lsd" name:"lsd"`
	Display              string `url:"display" name:"display"`
	IsPrivate            string `url:"isprivate" name:"isprivate"`
	ReturnSession        string `url:"return_session" name:"return_session"`
	SkipAPILogin         string `url:"skip_api_login" name:"skip_api_login"`
	SignedNext           string `url:"signed_next" name:"signed_next"`
	TryNum               string `url:"trynum" name:"trynum"`
	Timezone             string `url:"timezone"`
	Lgndim               string `url:"lgndim"`
	Lgnrnd               string `url:"lgnrnd" name:"lgnrnd"`
	Lgnjs                string `url:"lgnjs"`
	Email                string `url:"email"`
	PrefillContactPoint  string `url:"prefill_contact_point" name:"prefill_contact_point"`
	PrefillSource        string `url:"prefill_source" name:"prefill_source"`
	PrefillType          string `url:"prefill_type" name:"prefill_type"`
	FirstPrefillSource   string `url:"first_prefill_source" name:"first_prefill_source"`
	FirstPrefillType     string `url:"first_prefill_type" name:"first_prefill_type"`
	HadCPPrefilled       string `url:"had_cp_prefilled" name:"had_cp_prefilled"`
	HadPasswordPrefilled string `url:"had_password_prefilled" name:"had_password_prefilled"`
	AbTestData           string `url:"ab_test_data"`
	EncPass              string `url:"encpass"`
}

type LgnDim struct {
	W  int `json:"w,omitempty"`
	H  int `json:"h,omitempty"`
	Aw int `json:"aw,omitempty"`
	Ah int `json:"ah,omitempty"`
	C  int `json:"c,omitempty"`
}

type InstagramCookiesVariables struct {
	FirstPartyTrackingOptIn bool   `json:"first_party_tracking_opt_in,omitempty"`
	IgDid                   string `json:"ig_did,omitempty"`
	ThirdPartyTrackingOptIn bool   `json:"third_party_tracking_opt_in,omitempty"`
	Input                   struct {
		ClientMutationID int `json:"client_mutation_id,omitempty"`
	} `json:"input,omitempty"`
}

type InstagramLoginPayload struct {
	EncPassword                 string `url:"enc_password"`
	CaaF2DebugGroup             string `url:"caaF2DebugGroup"`
	IsPrivacyPortalReq          bool   `url:"isPrivacyPortalReq"`
	LoginAttemptSubmissionCount int    `url:"loginAttemptSubmissionCount"`
	OptIntoOneTap               bool   `url:"optIntoOneTap"`
	QueryParams                 string `url:"queryParams"`
	TrustedDeviceRecords        string `url:"trustedDeviceRecords"`
	Username                    string `url:"username"`
	Jazoest                     string `url:"jazoest"`
}

type InstagramLoginResponse struct {
	Message                   string                     `json:"message,omitempty"`
	TwoFactorRequired         bool                       `json:"two_factor_required,omitempty"`
	TwoFactorInfo             *TwoFactorInfo             `json:"two_factor_info,omitempty"`
	PhoneVerificationSettings *PhoneVerificationSettings `json:"phone_verification_settings,omitempty"`
	Status                    string                     `json:"status,omitempty"`
	ErrorType                 string                     `json:"error_type,omitempty"`
	Authenticated             bool                       `json:"authenticated,omitempty"`
	User                      bool                       `json:"user,omitempty"`
	UserID                    string                     `json:"userId,omitempty"`
	OneTapPrompt              bool                       `json:"oneTapPrompt,omitempty"`
	Reactivated               bool                       `json:"reactivated,omitempty"`
	CheckpointUrl             string                     `json:"checkpoint_url,omitempty"`
	FlowRenderType            int                        `json:"flow_render_type,omitempty"`
	Lock                      bool                       `json:"lock,omitempty"`

	// Newly added fields for extended response
	TrustedDeviceNonce        string `json:"trustedDeviceNonce,omitempty"`
	HasOnboardedToTextPostApp bool   `json:"has_onboarded_to_text_post_app,omitempty"`
	CryptedUid                string `json:"cryptedUid,omitempty"`
}

type TwoFactorInfo struct {
	PK                              string                     `json:"pk,omitempty"`
	Username                        string                     `json:"username,omitempty"`
	SmsTwoFactorOn                  bool                       `json:"sms_two_factor_on,omitempty"`
	WhatsappTwoFactorOn             bool                       `json:"whatsapp_two_factor_on,omitempty"`
	TotpTwoFactorOn                 bool                       `json:"totp_two_factor_on,omitempty"`
	EligibleForMultipleTotp         bool                       `json:"eligible_for_multiple_totp,omitempty"`
	ObfuscatedPhoneNumber           string                     `json:"obfuscated_phone_number,omitempty"`
	ObfuscatedPhoneNumber2          string                     `json:"obfuscated_phone_number_2,omitempty"`
	TwoFactorIdentifier             string                     `json:"two_factor_identifier,omitempty"`
	ShowMessengerCodeOption         bool                       `json:"show_messenger_code_option,omitempty"`
	ShowNewLoginScreen              bool                       `json:"show_new_login_screen,omitempty"`
	ShowTrustedDeviceOption         bool                       `json:"show_trusted_device_option,omitempty"`
	ShouldOptInTrustedDeviceOption  bool                       `json:"should_opt_in_trusted_device_option,omitempty"`
	PendingTrustedNotification      bool                       `json:"pending_trusted_notification,omitempty"`
	SmsNotAllowedReason             interface{}                `json:"sms_not_allowed_reason,omitempty"`
	TrustedNotificationPollingNonce interface{}                `json:"trusted_notification_polling_nonce,omitempty"`
	IsTrustedDevice                 bool                       `json:"is_trusted_device,omitempty"`
	DeviceID                        string                     `json:"device_id,omitempty"`
	IsInSowaExperience              bool                       `json:"is_in_sowa_experience,omitempty"`
	IsSowaWaffleEligible            bool                       `json:"is_sowa_waffle_eligible,omitempty"`
	PhoneVerificationSettings       *PhoneVerificationSettings `json:"phone_verification_settings,omitempty"`
}

type PhoneVerificationSettings struct {
	MaxSmsCount              int  `json:"max_sms_count,omitempty"`
	ResendSmsDelaySec        int  `json:"resend_sms_delay_sec,omitempty"`
	RobocallCountDownTimeSec int  `json:"robocall_count_down_time_sec,omitempty"`
	RobocallAfterMaxSms      bool `json:"robocall_after_max_sms,omitempty"`
}
