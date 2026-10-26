package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"aperire-advisor/internal/host"
)

// runWrapperCall is --wrapper-call: one call through the root socket with the
// same client the service uses, stdout to stdout, stderr and any failure to
// stderr, and the wrapper's own exit code as this process's (ADR 0025).
//
// It exists so the installers' prechecks and verify-baseline.sh test the
// Advisor's real route to root, as the Advisor's account and under
// no_new_privs, rather than a second client that could agree with the broker
// while this one did not.
func runWrapperCall(wrapper, sock string, args []string) int {
	if wrapper == "" || sock == "" {
		fmt.Fprintln(os.Stderr, "--wrapper-call needs --wrapper and --wrapper-socket")
		return 2
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "--wrapper-call needs a verb")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	out, err := host.ViaWrapper{Wrapper: wrapper, Socket: sock}.Run(ctx, wrapper, args...)
	os.Stdout.Write(out)
	if err == nil {
		return 0
	}
	fmt.Fprintln(os.Stderr, err)
	var we *host.WrapperExitError
	if errors.As(err, &we) && we.Code > 0 && we.Code < 256 {
		return we.Code
	}
	return 1
}
