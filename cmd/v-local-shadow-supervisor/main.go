//go:build darwin

package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/zanescope/v-local-key-provider/internal/shadowsupervisor"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "serve-fd" && os.Args[2] == "3" {
		if err := shadowsupervisor.ServeFD(3); err != nil {
			fmt.Fprintln(os.Stderr, "v-local-shadow-supervisor: controlled attempt failed")
			os.Exit(3)
		}
		return
	}
	if len(os.Args) >= 8 && os.Args[1] == "exec-gate" {
		gateFD, gateErr := strconv.Atoi(os.Args[2])
		statusFD, statusErr := strconv.Atoi(os.Args[3])
		if gateErr == nil && statusErr == nil {
			if err := shadowsupervisor.ExecGate(
				gateFD, statusFD, os.Args[4], os.Args[5], os.Args[6], os.Args[7], os.Args[8:],
			); err == nil {
				return
			}
		}
		fmt.Fprintln(os.Stderr, "v-local-shadow-supervisor: pre-exec gate failed")
		os.Exit(4)
	}
	fmt.Fprintln(os.Stderr, "v-local-shadow-supervisor: inherited control descriptor 3 is required")
	os.Exit(2)
}
