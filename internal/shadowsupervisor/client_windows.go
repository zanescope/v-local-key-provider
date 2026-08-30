//go:build windows

package shadowsupervisor

import (
	"context"
	"errors"
	"time"
)

type StartConfig struct {
	SupervisorPath   string
	SupervisorDigest string
	Init             Frame
	ResponseTimeout  time.Duration
}

type Client struct{}

func Start(context.Context, StartConfig) (*Client, Frame, error) {
	return nil, Frame{}, errors.New("Shadow supervisor client is unavailable on Windows")
}

func (*Client) SupervisorBound() Frame { return Frame{} }
func (*Client) Prepare(context.Context) (Frame, error) {
	return Frame{}, errors.New("Shadow supervisor client is unavailable on Windows")
}
func (*Client) Bound() Frame { return Frame{} }
func (*Client) Release(context.Context) error {
	return errors.New("Shadow supervisor client is unavailable on Windows")
}
func (*Client) Stop(context.Context) (bool, error) {
	return false, errors.New("Shadow supervisor client is unavailable on Windows")
}
func (*Client) CloseProvider(context.Context) (bool, error) {
	return false, errors.New("Shadow supervisor client is unavailable on Windows")
}
