package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	shadowmodel "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

const (
	Name                    = "v-local-key-provider/v1"
	MaxRequestBytes         = 1024 * 1024
	MaxResponseBytes        = 8 * 1024 * 1024
	MaxDeadlineMilliseconds = int64(3_600_000)
)

type ActionReceipt struct {
	Action                    string `json:"action"`
	UserConfirmed             bool   `json:"user_confirmed"`
	ObservedProcessTransition string `json:"observed_process_transition,omitempty"`
	ProcessInstanceID         string `json:"process_instance_id,omitempty"`
	Route                     string `json:"route,omitempty"`
	ActionStage               string `json:"action_stage,omitempty"`
}

type WorkflowRequest struct {
	Operation         string               `json:"operation"`
	SessionID         string               `json:"session_id,omitempty"`
	ExpectedCatalogID string               `json:"expected_catalog_id,omitempty"`
	ActionReceipt     *ActionReceipt       `json:"action_receipt,omitempty"`
	Shadow            *shadowmodel.Request `json:"shadow,omitempty"`
}

type AcquireRequest struct {
	Protocol   string          `json:"protocol"`
	RequestID  string          `json:"request_id"`
	Action     string          `json:"action"`
	CatalogKey string          `json:"catalog_key,omitempty"`
	AccountDir string          `json:"account_dir"`
	DBDir      string          `json:"db_dir"`
	Scopes     []string        `json:"scopes"`
	DeadlineMS int64           `json:"deadline_ms"`
	Workflow   WorkflowRequest `json:"workflow"`

	// PeerIdentity 是经过 transport 认证的元数据，绝不来自 JSON 请求正文，也不会出现在
	// 其中。
	PeerIdentity string `json:"-"`
}

type ImageKeys struct {
	AES string `json:"aes"`
	XOR int    `json:"xor"`
}

func ReadRequest(reader io.Reader) ([]byte, error) {
	limited := io.LimitReader(reader, MaxRequestBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, errors.New("读取请求失败")
	}
	if len(data) == 0 || len(data) > MaxRequestBytes {
		return nil, errors.New("请求为空或超过安全上限")
	}
	return data, nil
}

func DecodeRequestData(data []byte) (AcquireRequest, error) {
	var request AcquireRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return AcquireRequest{}, errors.New("请求不是有效的 JSON")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return AcquireRequest{}, errors.New("请求只能包含一个 JSON 对象")
	}
	if request.Protocol != Name {
		return AcquireRequest{}, fmt.Errorf("协议不匹配：收到 %q，需要 %q", request.Protocol, Name)
	}
	if request.DeadlineMS <= 0 || request.DeadlineMS > MaxDeadlineMilliseconds {
		return AcquireRequest{}, errors.New("deadline_ms 超出允许范围")
	}
	if request.Action != "acquire" {
		return AcquireRequest{}, errors.New("不支持的操作")
	}
	if request.RequestID == "" || len(request.RequestID) > 128 {
		return AcquireRequest{}, errors.New("request_id 无效")
	}
	switch request.Workflow.Operation {
	case "prepare", "observe", "finalize", "cancel", "revalidate_security_posture", "shadow":
	default:
		return AcquireRequest{}, errors.New("workflow.operation 无效")
	}
	switch request.Workflow.Operation {
	case "prepare":
		if request.Workflow.SessionID != "" || request.Workflow.ExpectedCatalogID != "" || request.Workflow.ActionReceipt != nil || request.Workflow.Shadow != nil {
			return AcquireRequest{}, errors.New("prepare 不能携带旧 session、catalog 或 action receipt")
		}
	case "observe":
		if request.Workflow.SessionID == "" || request.Workflow.ExpectedCatalogID == "" || request.Workflow.Shadow != nil {
			return AcquireRequest{}, errors.New("observe 必须绑定 session_id 和 expected_catalog_id")
		}
	case "finalize":
		if request.Workflow.ActionReceipt != nil || request.Workflow.Shadow != nil {
			return AcquireRequest{}, errors.New("action receipt 只能由 observe 提交")
		}
		if request.Workflow.SessionID != "" && request.Workflow.ExpectedCatalogID == "" {
			return AcquireRequest{}, errors.New("session finalize 必须绑定 expected_catalog_id")
		}
		if request.Workflow.SessionID == "" && request.Workflow.ExpectedCatalogID != "" {
			return AcquireRequest{}, errors.New("one-shot finalize 不能绑定不存在的 session catalog")
		}
	case "cancel":
		if request.Workflow.SessionID == "" || request.Workflow.ActionReceipt != nil || request.Workflow.Shadow != nil {
			return AcquireRequest{}, errors.New("cancel 必须绑定 session 且不能携带 action receipt")
		}
	case "revalidate_security_posture":
		if request.Workflow.SessionID != "" || request.Workflow.ExpectedCatalogID != "" || request.Workflow.ActionReceipt != nil || request.Workflow.Shadow != nil {
			return AcquireRequest{}, errors.New("安全姿态复核必须使用无旧 session、catalog 或 action receipt 的新请求")
		}
	case "shadow":
		if request.Workflow.SessionID != "" || request.Workflow.ExpectedCatalogID != "" || request.Workflow.ActionReceipt != nil || request.Workflow.Shadow == nil {
			return AcquireRequest{}, errors.New("Shadow 请求必须使用独立的一次性子契约")
		}
		if err := request.Workflow.Shadow.Validate(); err != nil || request.Workflow.Shadow.RequestID != request.RequestID {
			return AcquireRequest{}, errors.New("Shadow 子契约无效或没有绑定外层 request_id")
		}
		if request.DeadlineMS > 120_000 {
			return AcquireRequest{}, errors.New("Shadow 外层 deadline 不得超过固定 120 秒")
		}
	}
	return request, nil
}

func DecodeRequest(reader io.Reader) (AcquireRequest, error) {
	data, err := ReadRequest(reader)
	if err != nil {
		return AcquireRequest{}, err
	}
	return DecodeRequestData(data)
}
