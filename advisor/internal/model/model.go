// Package model reaches the operator's chosen language model.
//
// Three decisions from the knowledge base are enforced here rather than
// described somewhere else:
//
//   - The key is delivered as a systemd credential, never an environment
//     variable. It arrives as a file in $CREDENTIALS_DIRECTORY on a per-service
//     ramfs at 0400 and never enters the process environment, which closes
//     /proc/<pid>/environ, child-process inheritance and environment dumps
//     together. See model-credential-storage.md.
//
//   - The key belongs to the AGENT, never the executor. The executor is the
//     security boundary and has no reason to hold a model credential. Nothing
//     in internal/execute imports this package.
//
//   - The key must never reach a transcript, the action ledger, an ActionPlan,
//     or a log line. Redact() exists for that, and every error path here goes
//     through it. Storage hardening is worthless if the value is echoed
//     downstream.
//
// No provider is hardcoded. The operator names a base URL, a model, and an API
// shape. The model string is passed through untouched: if the provider does
// not recognise it, that error is surfaced verbatim rather than guessed at,
// because a wrong model name should say so instead of silently becoming a
// different model.
package model

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Shape is the request/response format a provider speaks.
type Shape string

const (
	// ShapeOpenAI covers /chat/completions, which xAI, OpenAI, Together,
	// Groq, OpenRouter, Ollama and most local runners all implement.
	ShapeOpenAI Shape = "openai"
	// ShapeAnthropic covers /v1/messages.
	ShapeAnthropic Shape = "anthropic"
)

// Config is what the operator writes. Note what is absent: the key.
type Config struct {
	Enabled bool   `json:"enabled" yaml:"enabled"`
	Shape   Shape  `json:"shape" yaml:"shape"`
	BaseURL string `json:"base_url" yaml:"base_url"`
	Model   string `json:"model" yaml:"model"`
	// CredentialName is the systemd credential to read from
	// $CREDENTIALS_DIRECTORY. Only a bare name — a path here would let the
	// config point the reader at any file the service can open.
	CredentialName string `json:"credential_name" yaml:"credential_name"`
	// KeyFile is the fallback for running outside systemd. Explicit, so that
	// choosing the weaker option is a thing the operator did on purpose.
	KeyFile string `json:"key_file" yaml:"key_file"`

	// KeyHint is the first six and last four characters of the sealed key,
	// joined by an ellipsis, the way every provider console shows it. It is
	// not a secret and it is not enough to use.
	//
	// The SEALER writes it, at the moment it seals the key. Nothing here
	// derives it: a service that computes the hint is a service that read
	// the key to build a display string, and the key is read here for
	// exactly one purpose, which is sending it. Absent on a host sealed
	// before the sealer wrote this field, and absent is published as no
	// hint rather than as a guess.
	KeyHint string `json:"key_hint,omitempty" yaml:"key_hint,omitempty"`

	MaxTokens int `json:"max_tokens" yaml:"max_tokens"`
	// Temperature is a pointer so "not set" and "set to zero" are different
	// things. Newer Anthropic models reject the parameter outright — sending a
	// default nobody chose turns a working key into a 400.
	Temperature *float64 `json:"temperature,omitempty" yaml:"temperature,omitempty"`
	TimeoutSec  int      `json:"timeout_sec" yaml:"timeout_sec"`
}

// DefaultConfig is what gets written for an operator to fill in. It is
// deliberately disabled and has no provider chosen: picking one for them would
// send their node's telemetry to a vendor they did not select.
func DefaultConfig() Config {
	return Config{
		Enabled:        false,
		Shape:          ShapeOpenAI,
		BaseURL:        "",
		Model:          "",
		CredentialName: "model-api-key",
		// Generous on purpose. 1200 cut a real answer off mid-sentence and
		// stopped another before it began, and the operator's next move was to
		// go and check their account balance. Output is billed per token used,
		// not per token allowed, so a high ceiling costs nothing on short
		// answers and simply stops truncating the long ones.
		MaxTokens: 16000,
		// 300s, not 60: a deep investigation gathers real evidence and writes a
		// full answer, which routinely runs past a chat-sized minute (operator
		// hit this as a provider timeout, 2026-08-14). The per-host model.json
		// overrides this; this is the compiled fallback for a config that omits it.
		TimeoutSec: 300,
	}
}

// LoadConfig reads the operator's file. A missing file is not an error: it
// means no model is configured, which is a supported state — Tier 1 is
// deterministic rules and runbooks and needs no key at all.
func LoadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Config{Enabled: false}, nil
	}
	if err != nil {
		return Config{}, err
	}
	c := DefaultConfig()
	if err := json.Unmarshal(raw, &c); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Validate reports why a config cannot be used, in the operator's terms.
func (c Config) Validate() error {
	if !c.Enabled {
		return fmt.Errorf("no model is configured")
	}
	if c.BaseURL == "" {
		return fmt.Errorf("base_url is empty — set your provider's API root")
	}
	if !strings.HasPrefix(c.BaseURL, "https://") && !strings.HasPrefix(c.BaseURL, "http://127.0.0.1") &&
		!strings.HasPrefix(c.BaseURL, "http://localhost") {
		return fmt.Errorf("base_url must be https, or loopback for a local runner")
	}
	if c.Model == "" {
		return fmt.Errorf("model is empty — set the model identifier your provider expects")
	}
	if c.Shape != ShapeOpenAI && c.Shape != ShapeAnthropic {
		return fmt.Errorf("shape must be %q or %q", ShapeOpenAI, ShapeAnthropic)
	}
	if c.CredentialName == "" && c.KeyFile == "" {
		return fmt.Errorf("neither credential_name nor key_file is set — the Advisor has no way to get a key")
	}
	if strings.ContainsAny(c.CredentialName, "/\\") {
		return fmt.Errorf("credential_name must be a bare name, not a path")
	}
	return nil
}

// Provider names the host this node's questions are sent to.
//
// Deliberately the same string a provider error carries ("api.anthropic.com
// said 401"): an operator comparing the model row on the dashboard against
// the error in their chat must not be given two different names for one
// destination. The port is kept for the same reason it is kept there — a
// local runner is only distinguishable by it.
func (c Config) Provider() string { return hostOf(c.BaseURL) }

// LoadKey resolves the API key, preferring the systemd credential.
//
// It is read at call time rather than cached at startup so that rotating the
// credential and restarting the unit is enough — there is no third place the
// old value can still be alive.
//
// A thin wrapper over resolveKey, which is the one place this file turns a
// configuration into bytes. CredentialPresent goes through the same
// function, which is what P2-080 asked for: a config CredentialPresent
// calls present is a config that can actually be used, mode bits and
// emptiness included, because there is only one resolver to disagree with
// itself.
func (c Config) LoadKey() (string, error) {
	return c.resolveKey()
}

func (c Config) resolveKey() (string, error) {
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" && c.CredentialName != "" {
		p := filepath.Join(dir, c.CredentialName)
		b, err := os.ReadFile(p)
		if err == nil {
			k, err := cleanKey(string(b))
			if err != nil {
				return "", fmt.Errorf("systemd credential %q: %w", c.CredentialName, err)
			}
			return k, nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("reading systemd credential %q: %w", c.CredentialName, err)
		}
	}
	if c.KeyFile == "" {
		return "", fmt.Errorf("no systemd credential %q and no key_file configured", c.CredentialName)
	}
	b, err := os.ReadFile(c.KeyFile)
	if err != nil {
		return "", fmt.Errorf("reading key_file: %w", err)
	}
	// A key file readable by anyone on the host is worth complaining about
	// while it is still cheap to fix.
	if fi, err := os.Stat(c.KeyFile); err == nil && fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("key_file %s is group- or world-readable (mode %04o); chmod 600 it",
			c.KeyFile, fi.Mode().Perm())
	}
	k, err := cleanKey(string(b))
	if err != nil {
		return "", fmt.Errorf("key_file %s: %w", c.KeyFile, err)
	}
	return k, nil
}

// CredentialPresent reports whether LoadKey would succeed right now.
//
// A config restored from a backup is not a credential restored with it.
// The systemd credential is sealed to the host that made it and does not
// survive a rebuild, so "the config validates" and "this Advisor can
// actually answer" are two different facts, and status.go's caller needs
// both.
//
// It calls the exact same resolveKey LoadKey does and keeps only whether it
// worked. An earlier version of this stopped at a stat, present meaning
// nothing more than a file exists at the path LoadKey would check, and that
// missed the two ways a file can sit there and still be useless: a key_file
// world- or group-readable, which LoadKey refuses outright, and a
// credential that reads back empty or all whitespace, which cleanKey
// refuses. A host in either shape reported `configured: true` while every
// question it asked failed. Going through resolveKey costs a read this is
// polled on every /v1/status request, but the key is never returned, logged
// or hashed here; it is discarded the moment the call above it returns.
func (c Config) CredentialPresent() bool {
	_, err := c.resolveKey()
	return err == nil
}

// cleanKey trims the key and refuses one that cannot go in a header.
//
// Without this the failure is Go's "invalid header field value for
// Authorization", which says nothing about which character is wrong or where
// it came from. A key that picked up a newline from a paste, or a smart quote
// from a document, should say so — that is a two-second fix once named and a
// long afternoon otherwise.
func cleanKey(raw string) (string, error) {
	k := strings.TrimSpace(raw)
	if k == "" {
		return "", fmt.Errorf("is empty")
	}
	for i, r := range k {
		// RFC 9110 field values: visible ASCII, space and tab. Anything else —
		// an embedded newline, a NUL, a curly quote pasted from a web page —
		// cannot be sent and must not be silently dropped.
		if r < 0x20 || r > 0x7e {
			return "", fmt.Errorf(
				"contains a character that cannot go in an HTTP header at position %d (%q). "+
					"That usually means the paste picked up a line break or a smart quote. "+
					"Re-seal it from Settings & Updates: press Change model or key under Advisor AI model.",
				i, r)
		}
	}
	if strings.ContainsAny(k, " \t") {
		return "", fmt.Errorf("contains a space or tab; the key was probably pasted with surrounding text")
	}
	return k, nil
}

// Turn is one message in the conversation.
type Turn struct {
	Role    string `json:"role"` // "user" or "assistant"
	Content string `json:"content"`
	// CacheBoundary marks the end of a stable prefix worth a provider-side
	// cache breakpoint — never set from JSON (the browser's posted history
	// never carries it), only by caller.go translating the ONE
	// interrogate.Message a caller marked, itself always the last entry of
	// an ask()/investigateContinue() seed (token-efficiency work, part 1;
	// see ask() in main.go). Anthropic looks up the longest matching cached
	// prefix on every call, so marking this turn is what lets round 2 of a
	// four-round investigation read this whole block back at the cache-read
	// rate instead of paying full input price for it again.
	CacheBoundary bool `json:"-"`
}

// Usage is what one model call cost, on both sides of the conversation.
//
// Read counts are the wrong unit for the interrogative loop's spend
// accounting: the reference block re-billed on every round of a multi-round
// question is tens of kilobytes, which dwarfs the cost of the reads
// themselves. Tokens are the only number that reflects what is actually
// billed, which is why this exists as a return value rather than something
// estimated afterward from string lengths.
type Usage struct {
	// PromptTokens is the TOTAL input-side token count this call was billed
	// for, whatever the per-token rate — fresh, cache-write, or cache-read.
	// CachedPromptTokens below is the subset of this number billed at the
	// provider's cache-read discount, never an addition to it.
	PromptTokens int
	// CachedPromptTokens is the subset of PromptTokens billed at the
	// provider's cache-read rate — Anthropic's cache_read_input_tokens, or
	// OpenAI's prompt_tokens_details.cached_tokens. Zero when the provider
	// reports nothing in that field, which is the honest reading for "no
	// cache hit" and for "this provider doesn't report the split" alike;
	// nothing downstream may treat a zero here as "definitely no discount",
	// only as "no discount counted." A cache WRITE (Anthropic's
	// cache_creation_input_tokens, billed at a ~25% premium, never a
	// discount) is folded into PromptTokens and deliberately excluded from
	// this field.
	CachedPromptTokens int
	CompletionTokens   int
	// Reported is false when the provider's response carried no usage block
	// at all — some local runners omit it entirely. Zeroes presented as a
	// measurement when nothing was reported would be the kept-versus-observed
	// defect in its cheapest form, so callers must check this before treating
	// the counts as real. Never estimated as a fallback.
	Reported bool
}

// Client talks to the provider.
type Client struct {
	Cfg  Config
	HTTP *http.Client
}

func New(c Config) *Client {
	t := c.TimeoutSec
	if t <= 0 {
		t = 60
	}
	return &Client{Cfg: c, HTTP: &http.Client{Timeout: time.Duration(t) * time.Second}}
}

// Ask sends the system prompt and conversation, and returns the reply plus
// what the call cost. Usage is returned alongside every reply, including
// error paths that still carry a usage block, so a caller summing spend
// across a multi-round loop never has to reason about which return path it
// came back through.
func (c *Client) Ask(ctx context.Context, system string, turns []Turn) (string, Usage, error) {
	if err := c.Cfg.Validate(); err != nil {
		return "", Usage{}, err
	}
	key, err := c.Cfg.LoadKey()
	if err != nil {
		return "", Usage{}, err
	}

	// Some providers reject temperature entirely. Ask once with it, and if that
	// is the only complaint, ask again without — an operator should not have to
	// know which models deprecated a parameter to get an answer.
	reply, usage, err := c.ask(ctx, system, turns, key, c.Cfg.Temperature)
	// A provider hiccup is not an answer. One 502 from the API went straight
	// through to the operator's chat mid-session; transient statuses get two
	// quiet retries with a short backoff before anyone is told anything.
	for attempt := 0; attempt < 2 && err != nil && transientProviderError(err); attempt++ {
		select {
		case <-ctx.Done():
			return "", Usage{}, ctx.Err()
		case <-time.After(time.Duration(2+3*attempt) * time.Second):
		}
		reply, usage, err = c.ask(ctx, system, turns, key, c.Cfg.Temperature)
	}
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "temperature") && c.Cfg.Temperature != nil {
		return c.ask(ctx, system, turns, key, nil)
	}
	return reply, usage, err
}

// transientProviderError matches the statuses worth retrying: rate limits,
// gateway errors, and Anthropic's 529 overloaded. "No such model" and auth
// failures are not on the list — retrying those just delays the truth.
func transientProviderError(err error) bool {
	e := err.Error()
	for _, s := range []string{" said 429", " said 500", " said 502",
		" said 503", " said 504", " said 529", "overloaded"} {
		if strings.Contains(e, s) {
			return true
		}
	}
	return false
}

func (c *Client) ask(ctx context.Context, system string, turns []Turn, key string, temp *float64) (string, Usage, error) {
	var url string
	var body []byte
	var err error

	switch c.Cfg.Shape {
	case ShapeAnthropic:
		// Two cache breakpoints (token-efficiency work, part 1). Anthropic
		// caches by exact prefix match over the ordered system + messages
		// blocks, up to 4 marked breakpoints per request; on a hit it
		// re-bills that whole prefix at ~10% of the fresh input rate. This
		// service uses two:
		//
		//  1. The system block — persona, standing rules, read menu and the
		//     selected knowledge, byte-identical across every round of one
		//     investigation and, barring a persona edit, a knowledge change
		//     or a fleet-roster change, across the next investigation too.
		//  2. The turn ask() marked CacheBoundary — the assembled reference
		//     material (measurements, ceremony state, lookups, fleet reads)
		//     plus the question, built once per ask() call and never
		//     mutated afterward. Marking it lets rounds 2-4 of the SAME
		//     four-round loop (interrogate.MaxModelCalls) read this block
		//     back cached instead of paying full price for it three more
		//     times — this is what "the loop's per-round calls reuse the
		//     identical prefix" means operationally, not just byte-for-byte.
		url = strings.TrimRight(c.Cfg.BaseURL, "/") + "/v1/messages"
		msgs := make([]map[string]any, 0, len(turns))
		for _, t := range turns {
			if t.CacheBoundary {
				msgs = append(msgs, map[string]any{
					"role": t.Role,
					"content": []map[string]any{
						{"type": "text", "text": t.Content, "cache_control": map[string]string{"type": "ephemeral"}},
					},
				})
				continue
			}
			msgs = append(msgs, map[string]any{"role": t.Role, "content": t.Content})
		}
		payload := map[string]any{
			"model": c.Cfg.Model, "messages": msgs,
			"max_tokens": c.Cfg.MaxTokens,
		}
		if system != "" {
			payload["system"] = []map[string]any{
				{"type": "text", "text": system, "cache_control": map[string]string{"type": "ephemeral"}},
			}
		}
		if temp != nil {
			payload["temperature"] = *temp
		}
		body, err = json.Marshal(payload)
	default:
		// The OpenAI /chat/completions shape has no cache_control directive
		// — there is nothing to add here. OpenAI's own automatic prefix
		// caching applies with no directive at all once a prompt crosses
		// ~1024 tokens and reports the hit back in
		// prompt_tokens_details.cached_tokens (mapped in parseReply below);
		// most /chat/completions-compatible runners this service talks to
		// either do the same or cache nothing, and there is no portable
		// knob across them to ask for it explicitly. Byte-identical
		// ordering — system first, unchanged menu and knowledge next, live
		// state last — is what this shape has to work with, and it is
		// enough for a provider that caches by prefix at all: the request
		// below produces the same bytes up to the live-state tail on every
		// round for exactly the reason the Anthropic branch marks
		// breakpoints for explicitly.
		url = strings.TrimRight(c.Cfg.BaseURL, "/") + "/chat/completions"
		msgs := []map[string]string{{"role": "system", "content": system}}
		for _, t := range turns {
			msgs = append(msgs, map[string]string{"role": t.Role, "content": t.Content})
		}
		payload := map[string]any{
			"model": c.Cfg.Model, "messages": msgs,
			"max_tokens": c.Cfg.MaxTokens,
		}
		if temp != nil {
			payload["temperature"] = *temp
		}
		body, err = json.Marshal(payload)
	}
	if err != nil {
		return "", Usage{}, err
	}

	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", Usage{}, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("User-Agent", "aperire-advisor/0.1")
	if c.Cfg.Shape == ShapeAnthropic {
		hreq.Header.Set("x-api-key", key)
		hreq.Header.Set("anthropic-version", "2023-06-01")
	} else {
		hreq.Header.Set("Authorization", "Bearer "+key)
	}

	resp, err := c.HTTP.Do(hreq)
	if err != nil {
		return "", Usage{}, fmt.Errorf("%s", Redact(err.Error(), key))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))

	if resp.StatusCode != http.StatusOK {
		// Surfaced verbatim, minus the key. A provider saying "no such model"
		// is the most useful thing an operator with a typo can be told, and
		// paraphrasing it into "the model failed" throws that away.
		return "", Usage{}, fmt.Errorf("%s said %s: %s",
			hostOf(url), resp.Status, Redact(strings.TrimSpace(string(raw)), key))
	}

	text, usage, err := parseReply(c.Cfg.Shape, raw, c.Cfg.MaxTokens)
	if err != nil {
		return "", usage, fmt.Errorf("%s", Redact(err.Error(), key))
	}
	return text, usage, nil
}

func parseReply(shape Shape, raw []byte, maxTokens int) (string, Usage, error) {
	if shape == ShapeAnthropic {
		var r struct {
			StopReason string `json:"stop_reason"`
			Content    []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			// A pointer so its absence is distinguishable from a reported
			// zero — see Usage.Reported.
			Usage *struct {
				InputTokens int `json:"input_tokens"`
				// CacheCreationInputTokens is the WRITE — billed at a
				// premium, never a discount — and CacheReadInputTokens is
				// the HIT, billed at the discount Usage.CachedPromptTokens
				// exists to surface. Absent entirely on a call that set no
				// cache_control, which unmarshals both to their zero value
				// and reproduces today's PromptTokens = InputTokens exactly
				// — nothing here changes what an uncached call reports.
				CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
				CacheReadInputTokens     int `json:"cache_read_input_tokens"`
				OutputTokens             int `json:"output_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return "", Usage{}, err
		}
		var usage Usage
		if r.Usage != nil {
			usage = Usage{
				PromptTokens:       r.Usage.InputTokens + r.Usage.CacheCreationInputTokens + r.Usage.CacheReadInputTokens,
				CachedPromptTokens: r.Usage.CacheReadInputTokens,
				CompletionTokens:   r.Usage.OutputTokens,
				Reported:           true,
			}
		}
		var b strings.Builder
		for _, c := range r.Content {
			if c.Type == "text" {
				b.WriteString(c.Text)
			}
		}
		if b.Len() == 0 {
			// The failure that cost an evening: the model spends output budget
			// on its own reasoning before any text, and a budget it exhausts
			// mid-thought yields a 200 with no text at all. Say which limit
			// was hit, or the operator is left staring at an empty success.
			//
			// Say what it is NOT, too. max_tokens is a per-request cap this
			// service sets; the first operator to hit it went and checked
			// their account balance, because "ran out of budget" reads as
			// money when you are the one paying for the key.
			if r.StopReason == "max_tokens" {
				return "", usage, fmt.Errorf("the answer needed more room than max_tokens allows, so the "+
					"provider stopped before writing any of it. This is a per-request limit in "+
					"advisor/state/model.json, not your account balance and not a rate limit — "+
					"raise max_tokens there (%d now) and ask again", maxTokens)
			}
			if r.StopReason != "" {
				return "", usage, fmt.Errorf("the provider returned no text (stop_reason %s)", r.StopReason)
			}
			return "", usage, fmt.Errorf("the provider returned no text")
		}
		// Text that stopped at the limit is a partial answer, and it does not
		// look like one — the first sign of this was a config summary that
		// ended mid-sentence, which reads as the model losing its thread
		// rather than as a budget this service set.
		if r.StopReason == "max_tokens" {
			b.WriteString("\n\n_(cut off here — the answer reached max_tokens, " +
				"currently " + strconv.Itoa(maxTokens) +
				" in advisor/state/model.json. Raise it, or ask for a narrower slice.)_")
		}
		return b.String(), usage, nil
	}
	var r struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage *struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			// PromptTokensDetails.CachedTokens is OpenAI's cache-read
			// count, already a SUBSET of PromptTokens above (unlike
			// Anthropic, which reports the fresh and cached portions as
			// separate counters) — nil on a provider that never fills this
			// in, which reproduces today's behaviour exactly.
			PromptTokensDetails *struct {
				CachedTokens int `json:"cached_tokens"`
			} `json:"prompt_tokens_details"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", Usage{}, err
	}
	var usage Usage
	if r.Usage != nil {
		usage = Usage{PromptTokens: r.Usage.PromptTokens, CompletionTokens: r.Usage.CompletionTokens, Reported: true}
		if r.Usage.PromptTokensDetails != nil {
			usage.CachedPromptTokens = r.Usage.PromptTokensDetails.CachedTokens
		}
	}
	if len(r.Choices) == 0 || strings.TrimSpace(r.Choices[0].Message.Content) == "" {
		return "", usage, fmt.Errorf("the provider returned no text")
	}
	return r.Choices[0].Message.Content, usage, nil
}

// Redact removes the key from anything on its way to a human, a log or the
// ledger. Also scrubs common bearer-token shapes, because a provider that
// echoes the Authorization header back in an error would otherwise leak it
// through a path the key-specific replace never sees.
func Redact(s, key string) string {
	if key != "" {
		s = strings.ReplaceAll(s, key, "[redacted]")
	}
	const mark = "[redacted]"
	for _, p := range []string{"Bearer ", "x-api-key: ", "xai-", "sk-"} {
		// Scan forward from a moving offset. Restarting from zero would find
		// the same prefix again — the substitution leaves the prefix in place —
		// and loop forever.
		off := 0
		for {
			i := strings.Index(s[off:], p)
			if i < 0 {
				break
			}
			i += off
			j := i + len(p)
			for j < len(s) && !isSep(s[j]) {
				j++
			}
			if j == i+len(p) {
				off = i + len(p) // nothing after the prefix to scrub
				continue
			}
			s = s[:i+len(p)] + mark + s[j:]
			off = i + len(p) + len(mark)
		}
	}
	return s
}

func isSep(b byte) bool {
	return b == ' ' || b == '"' || b == '\'' || b == '\n' || b == '\r' || b == ',' || b == '}' || b == ')'
}

func hostOf(u string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexByte(s, '/'); i > 0 {
		return s[:i]
	}
	return s
}
