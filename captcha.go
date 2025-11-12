package messagixplus

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	BaseURL       = "https://api.capsolver.com"
	CreateTaskURL = BaseURL + "/createTask"
	GetResultURL  = BaseURL + "/getTaskResult"
	GetBalanceURL = BaseURL + "/getBalance"
	FeedbackURL   = BaseURL + "/feedbackTask"

	MaxRetries   = 120
	PollInterval = 3 * time.Second
	TaskTimeout  = 5 * time.Minute
)

type CapSolver struct {
	ClientKey  string
	AppID      string
	HTTPClient *http.Client
}

func NewCapSolver(clientKey string) *CapSolver {
	return &CapSolver{
		ClientKey: clientKey,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

type ReCaptchaV2Task struct {
	Type        string `json:"type"`
	WebsiteURL  string `json:"websiteURL"`
	WebsiteKey  string `json:"websiteKey"`
	PageAction  string `json:"pageAction,omitempty"`
	IsInvisible bool   `json:"isInvisible,omitempty"`
	UserAgent   string `json:"userAgent,omitempty"`
	Proxy       string `json:"proxy,omitempty"`
}

type CreateTaskRequest struct {
	ClientKey   string      `json:"clientKey"`
	AppID       string      `json:"appId,omitempty"`
	Task        interface{} `json:"task"`
	CallbackURL string      `json:"callbackUrl,omitempty"`
}

type CreateTaskResponse struct {
	ErrorID          int    `json:"errorId"`
	ErrorCode        string `json:"errorCode"`
	ErrorDescription string `json:"errorDescription"`
	Status           string `json:"status"`
	Solution         string `json:"solution"`
	TaskID           string `json:"taskId"`
}

type GetTaskResultRequest struct {
	ClientKey string `json:"clientKey"`
	TaskID    string `json:"taskId"`
}

type GetTaskResultResponse struct {
	ErrorID          int         `json:"errorId"`
	ErrorCode        string      `json:"errorCode"`
	ErrorDescription string      `json:"errorDescription"`
	Status           string      `json:"status"`
	Solution         interface{} `json:"solution"`
}

type ReCaptchaV2Solution struct {
	GRecaptchaResponse string `json:"gRecaptchaResponse"`
	UserAgent          string `json:"userAgent,omitempty"`
}

type BalanceRequest struct {
	ClientKey string `json:"clientKey"`
}

type BalanceResponse struct {
	ErrorID          int           `json:"errorId"`
	ErrorCode        string        `json:"errorCode"`
	ErrorDescription string        `json:"errorDescription"`
	Balance          float64       `json:"balance"`
	Packages         []interface{} `json:"packages"`
}

func (c *CapSolver) makeRequest(url string, payload interface{}, response interface{}) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	if err := json.Unmarshal(body, response); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return nil
}

func (c *CapSolver) SolveReCaptchaV2(websiteURL, websiteKey string, options ...func(*ReCaptchaV2Task)) (*ReCaptchaV2Solution, error) {
	task := &ReCaptchaV2Task{
		Type:       "ReCaptchaV2TaskProxyless",
		WebsiteURL: websiteURL,
		WebsiteKey: websiteKey,
	}

	for _, option := range options {
		option(task)
	}

	createReq := &CreateTaskRequest{
		ClientKey: c.ClientKey,
		AppID:     c.AppID,
		Task:      task,
	}

	var createResp CreateTaskResponse
	if err := c.makeRequest(CreateTaskURL, createReq, &createResp); err != nil {
		return nil, fmt.Errorf("failed to create task: %w", err)
	}

	if createResp.ErrorID != 0 {
		return nil, fmt.Errorf("create task error: %s - %s", createResp.ErrorCode, createResp.ErrorDescription)
	}

	if createResp.TaskID == "" {
		return nil, errors.New("no task ID returned")
	}

	if createResp.Status == "ready" && createResp.Solution != "" {
		return &ReCaptchaV2Solution{
			GRecaptchaResponse: createResp.Solution,
		}, nil
	}

	return c.pollForResult(createResp.TaskID)
}

func (c *CapSolver) pollForResult(taskID string) (*ReCaptchaV2Solution, error) {
	startTime := time.Now()
	attempts := 0

	for attempts < MaxRetries && time.Since(startTime) < TaskTimeout {
		attempts++

		getReq := &GetTaskResultRequest{
			ClientKey: c.ClientKey,
			TaskID:    taskID,
		}

		var getResp GetTaskResultResponse
		if err := c.makeRequest(GetResultURL, getReq, &getResp); err != nil {
			return nil, fmt.Errorf("failed to get task result: %w", err)
		}

		if getResp.ErrorID != 0 {
			return nil, fmt.Errorf("get task result error: %s - %s", getResp.ErrorCode, getResp.ErrorDescription)
		}

		switch getResp.Status {
		case "ready":
			solutionBytes, err := json.Marshal(getResp.Solution)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal solution: %w", err)
			}

			var solution ReCaptchaV2Solution
			if err := json.Unmarshal(solutionBytes, &solution); err != nil {
				return nil, fmt.Errorf("failed to unmarshal solution: %w", err)
			}

			return &solution, nil
		case "processing":
			time.Sleep(PollInterval)
			continue
		case "idle":
			time.Sleep(PollInterval)
			continue
		default:
			return nil, fmt.Errorf("unknown task status: %s", getResp.Status)
		}
	}

	return nil, errors.New("task timed out or exceeded maximum retry attempts")
}

func (c *CapSolver) GetBalance() (*BalanceResponse, error) {
	req := &BalanceRequest{
		ClientKey: c.ClientKey,
	}

	var resp BalanceResponse
	if err := c.makeRequest(GetBalanceURL, req, &resp); err != nil {
		return nil, fmt.Errorf("failed to get balance: %w", err)
	}

	if resp.ErrorID != 0 {
		return nil, fmt.Errorf("get balance error: %s - %s", resp.ErrorCode, resp.ErrorDescription)
	}

	return &resp, nil
}

func WithInvisible(invisible bool) func(*ReCaptchaV2Task) {
	return func(task *ReCaptchaV2Task) {
		task.IsInvisible = invisible
	}
}

func WithUserAgent(userAgent string) func(*ReCaptchaV2Task) {
	return func(task *ReCaptchaV2Task) {
		task.UserAgent = userAgent
	}
}

func WithPageAction(action string) func(*ReCaptchaV2Task) {
	return func(task *ReCaptchaV2Task) {
		task.PageAction = action
	}
}

func WithProxy(proxy string) func(*ReCaptchaV2Task) {
	return func(task *ReCaptchaV2Task) {
		task.Proxy = proxy
		task.Type = "ReCaptchaV2Task"
	}
}
