package provider

import (
	"io"

	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
)

const (
	protocolName          = protocolmodel.Name
	maxRequestBytes       = protocolmodel.MaxRequestBytes
	maxResponseBytes      = protocolmodel.MaxResponseBytes
	maxBudgetMilliseconds = protocolmodel.MaxDeadlineMilliseconds
)

type actionReceipt = protocolmodel.ActionReceipt
type workflowRequest = protocolmodel.WorkflowRequest
type acquireRequest = protocolmodel.AcquireRequest
type imageKeys = protocolmodel.ImageKeys
type response = protocolmodel.Response

func readRequest(reader io.Reader) ([]byte, error) {
	return protocolmodel.ReadRequest(reader)
}

func decodeRequestData(data []byte) (acquireRequest, error) {
	return protocolmodel.DecodeRequestData(data)
}

func decodeRequest(reader io.Reader) (acquireRequest, error) {
	return protocolmodel.DecodeRequest(reader)
}
