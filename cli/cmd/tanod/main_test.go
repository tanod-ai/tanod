package main

import (
	"flag"
	"io"
	"testing"
)

func TestParseFlagsAllowsFlagsAfterPositionals(t *testing.T) {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	by := fs.String("by", "", "approver")
	role := fs.String("role", "", "role")

	if err := parseFlags(fs, []string{"appr_123", "--by", "ross@example.com", "--role=platform_owner"}); err != nil {
		t.Fatalf("parseFlags returned error: %v", err)
	}
	if got := fs.Arg(0); got != "appr_123" {
		t.Fatalf("position arg = %q, want appr_123", got)
	}
	if *by != "ross@example.com" {
		t.Fatalf("by = %q", *by)
	}
	if *role != "platform_owner" {
		t.Fatalf("role = %q", *role)
	}
}
