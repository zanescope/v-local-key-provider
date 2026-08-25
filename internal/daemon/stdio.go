package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
)

// RunStdio serves the legacy line-oriented daemon entry point with the same
// injected acquisition backend used by the authenticated native transport.
func (service *Service) RunStdio(reader io.Reader, writer io.Writer) error {
	backend := service.config.NewBackend(BackendContext{})
	if err := backend.validate(); err != nil {
		return err
	}
	defer backend.Close()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), protocolmodel.MaxRequestBytes)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		service.config.MarkSensitive(line)
		request, err := protocolmodel.DecodeRequestData(line)
		service.config.ZeroSensitive(line)
		if err != nil {
			return fmt.Errorf("daemon request invalid: %w", err)
		}
		result, err := backend.HandleContext(context.Background(), request)
		if err != nil {
			return err
		}
		if result.Protocol == "" {
			result.Protocol = protocolmodel.Name
		}
		if result.RequestID == "" {
			result.RequestID = request.RequestID
		}
		if err := encoder.Encode(result); err != nil {
			return errors.New("daemon response encoding failed")
		}
	}
	return scanner.Err()
}
