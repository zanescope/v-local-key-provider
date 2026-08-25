package provider

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

func runAcquisitionDaemon(reader io.Reader, writer io.Writer) error {
	store := newAcquisitionSessionStore()
	defer store.closeAll()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), maxRequestBytes)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		request, err := decodeRequestData(line)
		if err != nil {
			return fmt.Errorf("daemon request invalid: %w", err)
		}
		result, err := store.handle(request)
		if err != nil {
			return err
		}
		if result.Protocol == "" {
			result.Protocol = protocolName
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
