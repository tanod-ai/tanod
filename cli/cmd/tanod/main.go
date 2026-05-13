package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const defaultBaseURL = "http://127.0.0.1:8787"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		printHelp()
		return nil
	}

	client := newAPIClient()
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "decide":
		if len(rest) < 1 {
			return errors.New("usage: tanod decide <request.json>")
		}
		body, err := readJSONFile(rest[0])
		if err != nil {
			return err
		}
		return client.postJSON("/v1/decisions", body)
	case "execute":
		fs := flag.NewFlagSet("execute", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		token := fs.String("token", "", "approval token")
		if err := parseFlags(fs, rest); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return errors.New("usage: tanod execute <request.json> [--token <approval-token>]")
		}
		request, err := readJSONFile(fs.Arg(0))
		if err != nil {
			return err
		}
		payload := map[string]any{"request": request}
		if *token != "" {
			payload["approval_token"] = *token
		}
		return client.postJSON("/v1/executions", payload)
	case "request-approval":
		fs := flag.NewFlagSet("request-approval", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		by := fs.String("by", "", "requester")
		if err := parseFlags(fs, rest); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return errors.New("usage: tanod request-approval <request.json> [--by <user>]")
		}
		request, err := readJSONFile(fs.Arg(0))
		if err != nil {
			return err
		}
		payload := map[string]any{"request": request}
		if *by != "" {
			payload["requested_by"] = *by
		}
		return client.postJSON("/v1/approval-requests", payload)
	case "approvals":
		fs := flag.NewFlagSet("approvals", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		status := fs.String("status", "", "pending|approved|rejected|expired")
		if err := parseFlags(fs, rest); err != nil {
			return err
		}
		path := "/v1/approval-requests"
		if *status != "" {
			path += "?status=" + *status
		}
		return client.get(path)
	case "approve":
		fs := flag.NewFlagSet("approve", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		by := fs.String("by", "", "approver")
		role := fs.String("role", "", "approver role")
		ttl := fs.Int("ttl-seconds", 0, "approval token TTL seconds")
		if err := parseFlags(fs, rest); err != nil {
			return err
		}
		if fs.NArg() < 1 || *by == "" {
			return errors.New("usage: tanod approve <approval-id> --by <user> [--role <role>] [--ttl-seconds <seconds>]")
		}
		payload := map[string]any{"approved_by": *by}
		if *role != "" {
			payload["approved_role"] = *role
		}
		if *ttl > 0 {
			payload["ttl_seconds"] = *ttl
		}
		return client.postJSON("/v1/approval-requests/"+fs.Arg(0)+"/approve", payload)
	case "reject":
		fs := flag.NewFlagSet("reject", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		by := fs.String("by", "", "rejector")
		reason := fs.String("reason", "", "reason")
		if err := parseFlags(fs, rest); err != nil {
			return err
		}
		if fs.NArg() < 1 || *by == "" {
			return errors.New("usage: tanod reject <approval-id> --by <user> [--reason <reason>]")
		}
		payload := map[string]any{"rejected_by": *by}
		if *reason != "" {
			payload["reason"] = *reason
		}
		return client.postJSON("/v1/approval-requests/"+fs.Arg(0)+"/reject", payload)
	case "audit-verify":
		path := ".tanod/audit.jsonl"
		if len(rest) > 0 {
			path = rest[0]
		}
		return verifyAudit(path)
	default:
		return fmt.Errorf("unknown command: %s. Run tanod help", cmd)
	}
}

func parseFlags(fs *flag.FlagSet, args []string) error {
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--") || strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			if !strings.Contains(arg, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		positionals = append(positionals, arg)
	}
	return fs.Parse(append(flags, positionals...))
}

type apiClient struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

func newAPIClient() apiClient {
	baseURL := strings.TrimRight(os.Getenv("TANOD_URL"), "/")
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return apiClient{baseURL: baseURL, apiKey: os.Getenv("TANOD_API_KEY"), http: &http.Client{Timeout: 30 * time.Second}}
}

func (c apiClient) get(path string) error {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	return c.do(req)
}

func (c apiClient) postJSON(path string, body any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	return c.do(req)
}

func (c apiClient) do(req *http.Request) error {
	if c.apiKey != "" {
		req.Header.Set("authorization", "Bearer "+c.apiKey)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	printJSON(body)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("request failed: %s", res.Status)
	}
	return nil
}

func readJSONFile(path string) (any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return value, nil
}

func printJSON(raw []byte) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		fmt.Println(string(raw))
		return
	}
	formatted, _ := json.MarshalIndent(value, "", "  ")
	fmt.Println(string(formatted))
}

func verifyAudit(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) == 1 && strings.TrimSpace(lines[0]) == "" {
		lines = nil
	}
	previous := any(nil)
	for i, line := range lines {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return fmt.Errorf("line %d: %w", i+1, err)
		}
		eventHash, ok := event["event_hash"].(string)
		if !ok || eventHash == "" {
			return fmt.Errorf("line %d missing event_hash", i+1)
		}
		if !jsonEqual(event["previous_hash"], previous) {
			return fmt.Errorf("line %d previous_hash mismatch", i+1)
		}
		delete(event, "event_hash")
		canonical, err := json.Marshal(event)
		if err != nil {
			return err
		}
		hash := sha256.Sum256(canonical)
		expected := "sha256:" + hex.EncodeToString(hash[:])
		if eventHash != expected {
			return fmt.Errorf("line %d event_hash mismatch", i+1)
		}
		previous = eventHash
	}
	result := map[string]any{"valid": true, "events": len(lines), "file": path}
	formatted, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(formatted))
	return nil
}

func jsonEqual(a, b any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return bytes.Equal(ab, bb)
}

func printHelp() {
	fmt.Println(`tanod commands:
  tanod decide <request.json>
  tanod execute <request.json> [--token <approval-token>]
  tanod request-approval <request.json> [--by <user>]
  tanod approvals [--status pending|approved|rejected|expired]
  tanod approve <approval-id> --by <user> [--role <role>] [--ttl-seconds <seconds>]
  tanod reject <approval-id> --by <user> [--reason <reason>]
  tanod audit-verify [audit.jsonl]

Environment:
  TANOD_URL=http://127.0.0.1:8787
  TANOD_API_KEY=<key if server uses TANOD_API_KEYS>`)
}
