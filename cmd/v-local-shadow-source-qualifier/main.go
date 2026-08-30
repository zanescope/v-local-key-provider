package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	shadowsource "github.com/zanescope/v-local-key-provider/internal/shadowsource"
)

const maxInputBytes = int64(1024 * 1024)

func readJSON(path string, destination any) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maxInputBytes {
		return errors.New("qualification input file is invalid")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return errors.New("qualification input file is unreadable")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("qualification input JSON is invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("qualification input JSON has trailing data")
	}
	return nil
}

func run() error {
	mode := flag.String("mode", "", "inspect or qualify")
	source := flag.String("source", "/Applications/WeChat.app", "canonical source App path")
	referencesPath := flag.String("references", "", "rewrite-reference JSON path")
	manifestPath := flag.String("manifest", "", "frozen source-manifest JSON path")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	inspector := shadowsource.Inspector{}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	switch *mode {
	case "inspect":
		if *referencesPath == "" || *manifestPath != "" {
			return errors.New("inspect mode requires only --references")
		}
		var references []shadowsource.RewriteReference
		if err := readJSON(*referencesPath, &references); err != nil {
			return err
		}
		result, err := inspector.Inspect(ctx, *source, references)
		if err != nil {
			return err
		}
		return encoder.Encode(result)
	case "qualify":
		if *manifestPath == "" || *referencesPath != "" {
			return errors.New("qualify mode requires only --manifest")
		}
		var manifest shadowsource.Manifest
		if err := readJSON(*manifestPath, &manifest); err != nil {
			return err
		}
		result, err := inspector.Qualify(ctx, *source, manifest)
		if err != nil {
			return err
		}
		return encoder.Encode(result)
	default:
		return errors.New("qualification mode is invalid")
	}
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
