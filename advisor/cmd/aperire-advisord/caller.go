package main

import (
	"context"
	"log"
	"time"

	"aperire-advisor/internal/interrogate"
	"aperire-advisor/internal/model"
)

// modelCaller adapts *model.Client to interrogate.Caller. internal/interrogate
// holds its own Message/Usage types rather than importing internal/model (its
// own doc comment: "zero imports of sibling advisor/internal/* packages" —
// deliberate, so the package carrying the security properties stays
// reviewable on its own). This is the one seam that translates between the
// two shapes, once, rather than every call site doing it inline.
type modelCaller struct {
	client *model.Client
}

// Ask satisfies interrogate.Caller. The system prompt travels inside
// messages as a Role: "system" entry — the same convention
// internal/interrogate's own tests already assume (loop_test.go seeds every
// scripted run with one) — and is pulled back out here because
// model.Client.Ask wants it as a separate parameter. Extracted fresh on
// every call rather than cached at construction: the loop's seed carries
// exactly one system message and never removes or replaces it, so this is
// equivalent to holding it once, but it means this adapter has no state a
// future change to how the loop assembles messages could get out of sync
// with.
func (c *modelCaller) Ask(ctx context.Context, messages []interrogate.Message) (string, interrogate.Usage, error) {
	var system string
	turns := make([]model.Turn, 0, len(messages))
	for _, m := range messages {
		if m.Role == "system" {
			system = m.Content
			continue
		}
		turns = append(turns, model.Turn{Role: m.Role, Content: m.Content, CacheBoundary: m.CacheBoundary})
	}
	started := time.Now()
	reply, usage, err := c.client.Ask(ctx, system, turns)
	// One line per model call, with what it cost in TIME. The end-of-ask
	// "[ask] N rounds ... 12.4s" line reports the whole question, which
	// cannot answer the question #72 raised: whether a confirm turn is slow
	// because of many rounds or one long one. Sized in bytes rather than
	// tokens because that is what this side actually knows before the
	// provider answers, and it is the number that moves when the prompt
	// grows. Nothing of the prompt or the reply is logged.
	log.Printf("[model] call finished in %s: %d turns, %d prompt bytes, %d reply bytes, err=%v",
		time.Since(started).Round(time.Millisecond), len(turns),
		len(system)+promptBytes(turns), len(reply), err)
	return reply, interrogate.Usage{
		PromptTokens:       usage.PromptTokens,
		CachedPromptTokens: usage.CachedPromptTokens,
		CompletionTokens:   usage.CompletionTokens,
		Reported:           usage.Reported,
	}, err
}

// promptBytes is the size of what was sent, not of what it means. Used only
// in the log line above.
func promptBytes(turns []model.Turn) int {
	n := 0
	for _, t := range turns {
		n += len(t.Content)
	}
	return n
}
