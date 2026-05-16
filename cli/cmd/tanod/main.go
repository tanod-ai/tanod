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
	"net/url"
	"os"
	"os/user"
	"path/filepath"
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
		by := fs.String("by", "", "approver; defaults to <user>@<hostname>")
		role := fs.String("role", "", "approver role")
		ttl := fs.Int("ttl-seconds", 0, "approval token TTL seconds")
		if err := parseFlags(fs, rest); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return errors.New("usage: tanod approve <approval-id> [--by <user>] [--role <role>] [--ttl-seconds <seconds>]")
		}
		approver := *by
		if approver == "" {
			var err error
			approver, err = osIdentity()
			if err != nil {
				return err
			}
		}
		payload := map[string]any{"approved_by": approver}
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
		by := fs.String("by", "", "rejector; defaults to <user>@<hostname>")
		reason := fs.String("reason", "", "reason")
		if err := parseFlags(fs, rest); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return errors.New("usage: tanod reject <approval-id> [--by <user>] [--reason <reason>]")
		}
		rejector := *by
		if rejector == "" {
			var err error
			rejector, err = osIdentity()
			if err != nil {
				return err
			}
		}
		payload := map[string]any{"rejected_by": rejector}
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
	case "config":
		return runConfig(rest)
	case "user":
		return runUser(client, rest)
	default:
		return fmt.Errorf("unknown command: %s. Run tanod help", cmd)
	}
}

type userRecord struct {
	UserID      string   `json:"user_id"`
	Identity    string   `json:"identity"`
	DisplayName string   `json:"display_name"`
	Roles       []string `json:"roles"`
	Status      string   `json:"status"`
}

type usersResponse struct {
	Users []userRecord `json:"users"`
}

func runUser(client apiClient, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: tanod user ls|add|delete|<user-id> add-role|remove-roles")
	}
	switch args[0] {
	case "ls":
		return client.get("/v1/users")
	case "add":
		if len(args) < 4 {
			return errors.New("usage: tanod user add <user-id> <display-name> <role> [role2] [role3]")
		}
		return client.postJSON("/v1/users", map[string]any{
			"user_id":      args[1],
			"display_name": args[2],
			"roles":        args[3:],
		})
	case "delete":
		if len(args) != 2 {
			return errors.New("usage: tanod user delete <user-id>")
		}
		return client.delete("/v1/users/" + url.PathEscape(args[1]))
	default:
		if len(args) != 3 {
			return errors.New("usage: tanod user <user-id> add-role <role-name> | tanod user <user-id> remove-roles <role-name>")
		}
		userID, action, role := args[0], args[1], args[2]
		users, err := client.fetchUsers()
		if err != nil {
			return err
		}
		var current *userRecord
		for i := range users.Users {
			if users.Users[i].UserID == userID || users.Users[i].Identity == userID {
				current = &users.Users[i]
				break
			}
		}
		if current == nil {
			return fmt.Errorf("user not found: %s", userID)
		}
		roles := current.Roles
		switch action {
		case "add-role":
			if !containsString(roles, role) {
				roles = append(roles, role)
			}
		case "remove-roles":
			roles = removeString(roles, role)
			if len(roles) == 0 {
				return errors.New("user must have at least one role")
			}
		default:
			return errors.New("usage: tanod user <user-id> add-role <role-name> | tanod user <user-id> remove-roles <role-name>")
		}
		return client.patchJSON("/v1/users/"+url.PathEscape(userID), map[string]any{"roles": roles})
	}
}

func containsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func removeString(values []string, value string) []string {
	next := values[:0]
	for _, item := range values {
		if item != value {
			next = append(next, item)
		}
	}
	return next
}

func osIdentity() (string, error) {
	current, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("resolve current OS user: %w", err)
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("resolve hostname: %w", err)
	}
	username := current.Username
	if idx := strings.LastIndexAny(username, "\\/"); idx >= 0 {
		username = username[idx+1:]
	}
	return username + "@" + hostname, nil
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

type configFile struct {
	BaseURL         string                 `json:"base_url,omitempty"`
	APIKey          string                 `json:"api_key,omitempty"`
	OIDCProviders   []oidcProviderConfig   `json:"oidc_providers,omitempty"`
	OAuth2Providers []oauth2ProviderConfig `json:"oauth2_providers,omitempty"`
}

type oidcProviderConfig struct {
	ID       string `json:"id"`
	Label    string `json:"label,omitempty"`
	Issuer   string `json:"issuer"`
	Audience string `json:"audience,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	JWKSURI  string `json:"jwks_uri,omitempty"`
	Scope    string `json:"scope,omitempty"`
}

type oauth2ProviderConfig struct {
	ID               string `json:"id"`
	Label            string `json:"label,omitempty"`
	ClientID         string `json:"client_id"`
	ClientSecret     string `json:"client_secret"`
	AuthorizationURL string `json:"authorization_url"`
	TokenURL         string `json:"token_url"`
	UserURL          string `json:"user_url"`
	EmailsURL        string `json:"emails_url,omitempty"`
	Scope            string `json:"scope,omitempty"`
}

func runConfig(args []string) error {
	if len(args) == 0 || args[0] == "get" {
		cfg, err := loadConfigFile()
		if err != nil {
			return err
		}
		formatted, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(formatted))
		return nil
	}
	switch args[0] {
	case "path":
		fmt.Println(configPath())
		return nil
	case "set":
		if len(args) < 3 {
			return errors.New("usage: tanod config set base-url|api-key <value>")
		}
		cfg, err := loadConfigFile()
		if err != nil {
			return err
		}
		switch args[1] {
		case "base-url":
			cfg.BaseURL = strings.TrimRight(args[2], "/")
		case "api-key":
			cfg.APIKey = args[2]
		default:
			return errors.New("usage: tanod config set base-url|api-key <value>")
		}
		return saveConfigFile(cfg)
	case "unset":
		if len(args) < 2 {
			return errors.New("usage: tanod config unset api-key|base-url")
		}
		cfg, err := loadConfigFile()
		if err != nil {
			return err
		}
		switch args[1] {
		case "base-url":
			cfg.BaseURL = ""
		case "api-key":
			cfg.APIKey = ""
		default:
			return errors.New("usage: tanod config unset api-key|base-url")
		}
		return saveConfigFile(cfg)
	case "oidc":
		return runConfigOIDC(args[1:])
	case "oauth":
		return runConfigOAuth2(args[1:])
	default:
		return errors.New("usage: tanod config get|path|set|unset|oidc|oauth")
	}
}

func runConfigOAuth2(args []string) error {
	if len(args) == 0 || args[0] == "list" {
		cfg, err := loadConfigFile()
		if err != nil {
			return err
		}
		formatted, _ := json.MarshalIndent(cfg.OAuth2Providers, "", "  ")
		fmt.Println(string(formatted))
		return nil
	}
	switch args[0] {
	case "add":
		return addOAuth2Provider(args[1:])
	case "remove":
		if len(args) < 2 {
			return errors.New("usage: tanod config oauth remove <id>")
		}
		cfg, err := loadConfigFile()
		if err != nil {
			return err
		}
		next := cfg.OAuth2Providers[:0]
		for _, provider := range cfg.OAuth2Providers {
			if provider.ID != args[1] {
				next = append(next, provider)
			}
		}
		cfg.OAuth2Providers = next
		return saveConfigFile(cfg)
	default:
		return errors.New("usage: tanod config oauth list|add|remove")
	}
}

func addOAuth2Provider(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: tanod config oauth add github --client-id <id> --client-secret <secret> [--scope <scope>]")
	}
	providerID := args[0]
	fs := flag.NewFlagSet("config oauth add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	clientID := fs.String("client-id", "", "OAuth2 client id")
	clientSecret := fs.String("client-secret", "", "OAuth2 client secret")
	label := fs.String("label", "", "display label")
	authorizationURL := fs.String("authorization-url", "", "authorization URL")
	tokenURL := fs.String("token-url", "", "token URL")
	userURL := fs.String("user-url", "", "user profile URL")
	emailsURL := fs.String("emails-url", "", "user emails URL")
	scope := fs.String("scope", "", "OAuth2 scope")
	if err := parseFlags(fs, args[1:]); err != nil {
		return err
	}
	if *clientID == "" || *clientSecret == "" {
		return errors.New("--client-id and --client-secret are required")
	}
	next, err := presetOAuth2Provider(providerID, *clientID, *clientSecret, *label, *authorizationURL, *tokenURL, *userURL, *emailsURL, *scope)
	if err != nil {
		return err
	}
	cfg, err := loadConfigFile()
	if err != nil {
		return err
	}
	replaced := false
	for i, existing := range cfg.OAuth2Providers {
		if existing.ID == providerID {
			cfg.OAuth2Providers[i] = next
			replaced = true
			break
		}
	}
	if !replaced {
		cfg.OAuth2Providers = append(cfg.OAuth2Providers, next)
	}
	return saveConfigFile(cfg)
}

func presetOAuth2Provider(id, clientID, clientSecret, label, authorizationURL, tokenURL, userURL, emailsURL, scope string) (oauth2ProviderConfig, error) {
	if id == "github" {
		return oauth2ProviderConfig{
			ID:               "github",
			Label:            envOr(label, "GitHub"),
			ClientID:         clientID,
			ClientSecret:     clientSecret,
			AuthorizationURL: envOr(authorizationURL, "https://github.com/login/oauth/authorize"),
			TokenURL:         envOr(tokenURL, "https://github.com/login/oauth/access_token"),
			UserURL:          envOr(userURL, "https://api.github.com/user"),
			EmailsURL:        envOr(emailsURL, "https://api.github.com/user/emails"),
			Scope:            envOr(scope, "read:user user:email"),
		}, nil
	}
	if authorizationURL == "" || tokenURL == "" || userURL == "" {
		return oauth2ProviderConfig{}, fmt.Errorf("custom OAuth2 provider %s requires --authorization-url, --token-url, and --user-url", id)
	}
	return oauth2ProviderConfig{
		ID:               id,
		Label:            envOr(label, id),
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		AuthorizationURL: authorizationURL,
		TokenURL:         tokenURL,
		UserURL:          userURL,
		EmailsURL:        emailsURL,
		Scope:            scope,
	}, nil
}

func runConfigOIDC(args []string) error {
	if len(args) == 0 || args[0] == "list" {
		cfg, err := loadConfigFile()
		if err != nil {
			return err
		}
		formatted, _ := json.MarshalIndent(cfg.OIDCProviders, "", "  ")
		fmt.Println(string(formatted))
		return nil
	}
	switch args[0] {
	case "add":
		return addOIDCProvider(args[1:])
	case "remove":
		if len(args) < 2 {
			return errors.New("usage: tanod config oidc remove <id>")
		}
		cfg, err := loadConfigFile()
		if err != nil {
			return err
		}
		next := cfg.OIDCProviders[:0]
		for _, provider := range cfg.OIDCProviders {
			if provider.ID != args[1] {
				next = append(next, provider)
			}
		}
		cfg.OIDCProviders = next
		return saveConfigFile(cfg)
	default:
		return errors.New("usage: tanod config oidc list|add|remove")
	}
}

func addOIDCProvider(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: tanod config oidc add <github|google|microsoft|custom> --client-id <id> [--audience <aud>] [--issuer <url>] [--tenant <tenant>] [--label <label>] [--jwks-uri <url>]")
	}
	providerID := args[0]
	fs := flag.NewFlagSet("config oidc add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	clientID := fs.String("client-id", "", "OAuth/OIDC client id")
	audience := fs.String("audience", "", "JWT audience; defaults to client id")
	issuer := fs.String("issuer", "", "OIDC issuer")
	tenant := fs.String("tenant", "common", "Microsoft Entra tenant id")
	label := fs.String("label", "", "display label")
	jwksURI := fs.String("jwks-uri", "", "JWKS URI override")
	scope := fs.String("scope", "openid email profile", "OAuth/OIDC scope")
	if err := parseFlags(fs, args[1:]); err != nil {
		return err
	}
	if *clientID == "" {
		return errors.New("--client-id is required")
	}
	resolvedIssuer, resolvedLabel, err := presetOIDCProvider(providerID, *issuer, *tenant, *label)
	if err != nil {
		return err
	}
	resolvedAudience := *audience
	if resolvedAudience == "" {
		resolvedAudience = *clientID
	}
	cfg, err := loadConfigFile()
	if err != nil {
		return err
	}
	next := oidcProviderConfig{
		ID:       providerID,
		Label:    resolvedLabel,
		Issuer:   strings.TrimRight(resolvedIssuer, "/"),
		Audience: resolvedAudience,
		ClientID: *clientID,
		JWKSURI:  *jwksURI,
		Scope:    *scope,
	}
	replaced := false
	for i, existing := range cfg.OIDCProviders {
		if existing.ID == providerID {
			cfg.OIDCProviders[i] = next
			replaced = true
			break
		}
	}
	if !replaced {
		cfg.OIDCProviders = append(cfg.OIDCProviders, next)
	}
	return saveConfigFile(cfg)
}

func presetOIDCProvider(id, issuer, tenant, label string) (string, string, error) {
	switch id {
	case "google":
		return envOr(issuer, "https://accounts.google.com"), envOr(label, "Google"), nil
	case "microsoft":
		if tenant == "" {
			tenant = "common"
		}
		return envOr(issuer, "https://login.microsoftonline.com/"+tenant+"/v2.0"), envOr(label, "Microsoft Entra ID"), nil
	case "github":
		if issuer == "" {
			return "", "", errors.New("GitHub browser sign-in requires a GitHub-compatible OIDC issuer; pass --issuer for your OAuth/OIDC broker")
		}
		return issuer, envOr(label, "GitHub"), nil
	case "custom":
		if issuer == "" {
			return "", "", errors.New("--issuer is required for custom providers")
		}
		return issuer, envOr(label, "Custom"), nil
	default:
		if issuer == "" {
			return "", "", fmt.Errorf("--issuer is required for provider %s", id)
		}
		return issuer, envOr(label, id), nil
	}
}

func configPath() string {
	if path := os.Getenv("TANOD_CONFIG_FILE"); path != "" {
		return path
	}
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return filepath.Join(".config", "tanod", "config.json")
		}
		configHome = filepath.Join(home, ".config")
	}
	return filepath.Join(configHome, "tanod", "config.json")
}

func loadConfigFile() (configFile, error) {
	raw, err := os.ReadFile(configPath())
	if errors.Is(err, os.ErrNotExist) {
		return configFile{}, nil
	}
	if err != nil {
		return configFile{}, err
	}
	var cfg configFile
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return configFile{}, fmt.Errorf("parse %s: %w", configPath(), err)
	}
	return cfg, nil
}

func saveConfigFile(cfg configFile) error {
	path := configPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

func envOr(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func newAPIClient() apiClient {
	cfg, _ := loadConfigFile()
	baseURL := strings.TrimRight(envOr(os.Getenv("TANOD_URL"), cfg.BaseURL), "/")
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return apiClient{baseURL: baseURL, apiKey: envOr(os.Getenv("TANOD_API_KEY"), cfg.APIKey), http: &http.Client{Timeout: 30 * time.Second}}
}

func (c apiClient) get(path string) error {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	return c.do(req)
}

func (c apiClient) postJSON(path string, body any) error {
	return c.jsonRequest(http.MethodPost, path, body)
}

func (c apiClient) patchJSON(path string, body any) error {
	return c.jsonRequest(http.MethodPatch, path, body)
}

func (c apiClient) jsonRequest(method, path string, body any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, c.baseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	return c.do(req)
}

func (c apiClient) delete(path string) error {
	req, err := http.NewRequest(http.MethodDelete, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	return c.do(req)
}

func (c apiClient) fetchUsers() (usersResponse, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+"/v1/users", nil)
	if err != nil {
		return usersResponse{}, err
	}
	body, err := c.doBytes(req)
	if err != nil {
		return usersResponse{}, err
	}
	var users usersResponse
	if err := json.Unmarshal(body, &users); err != nil {
		return usersResponse{}, err
	}
	return users, nil
}

func (c apiClient) do(req *http.Request) error {
	body, err := c.doBytes(req)
	if err != nil {
		if len(body) > 0 {
			printJSON(body)
		}
		return err
	}
	printJSON(body)
	return nil
}

func (c apiClient) doBytes(req *http.Request) ([]byte, error) {
	if c.apiKey != "" {
		req.Header.Set("authorization", "Bearer "+c.apiKey)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return body, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return body, fmt.Errorf("request failed: %s", res.Status)
	}
	return body, nil
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
  tanod approve <approval-id> [--by <user>] [--role <role>] [--ttl-seconds <seconds>]
  tanod reject <approval-id> [--by <user>] [--reason <reason>]
  tanod user ls
  tanod user add <user-id> <display-name> <role> [role2] [role3]
  tanod user <user-id> add-role <role-name>
  tanod user <user-id> remove-roles <role-name>
  tanod user delete <user-id>
  tanod audit-verify [audit.jsonl]
  tanod config get|path
  tanod config set base-url|api-key <value>
  tanod config unset base-url|api-key
  tanod config oidc list
  tanod config oidc add <google|microsoft|github|custom> --client-id <id> [--audience <aud>] [--issuer <url>] [--tenant <tenant>]
  tanod config oidc remove <id>
  tanod config oauth list
  tanod config oauth add github --client-id <id> --client-secret <secret>
  tanod config oauth remove <id>

Environment:
  TANOD_URL=http://127.0.0.1:8787
  TANOD_API_KEY=<key if server uses TANOD_API_KEYS>
  TANOD_CONFIG_FILE=<path to config.json>`)
}
