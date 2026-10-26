package main

import (
	"fmt"
	"log"
	"time"

	"aperire-advisor/internal/approval"
	"aperire-advisor/internal/ledger"
	"aperire-advisor/internal/runbook"
)

// refusedPlanChanged is the reason a run gives when the plan this node
// derives now is not the plan the operator approved (#1029).
const refusedPlanChanged = "plan_changed"

// planMovedRefusal is /v1/execute's answer when there is no approval for the
// rollback this node derives now, and there IS a live approval for another
// rollback plan on the same node, covering the same stage. Nil
// otherwise: no approval at all is the ordinary refusal RunStage gives, and
// an approval for this plan is the run going ahead.
//
// The operator approved a plan and the node's own answer moved before the
// run. A run against the moved plan is not the one approved, and neither is
// a run against the approved one with facts that no longer hold. So nothing
// runs, the approval is left standing (asking again mints a fresh gate), and
// the refusal is recorded with both plan ids.
func (s *server) planMovedRefusal(dir string, rb runbook.Runbook, node, planID, fp, stage string,
	params runbook.Params, in planParams) map[string]any {
	// A rollback, and the upgrade's image source. Those two plans hold
	// facts that are the node's to derive and are re-derived at the run, so
	// a different plan there is the node's answer moving. Any other
	// runbook's plan is what the request asked for, and a different one is
	// a different request, which RunStage refuses as unapproved.
	if rb.DeclaresParam("digest") {
		return s.sourceMovedRefusal(dir, rb, node, planID, fp, stage, params, in)
	}
	if rb.ID != rollbackRunbookID {
		return nil
	}
	now := time.Now()
	if _, err := approval.Check(dir, planID, fp, node, stage, now); err == nil {
		return nil
	}
	var approved *approval.Approval
	for _, a := range approval.LiveFor(dir, rb.ID, node, stage, now) {
		if a.PlanID != planID {
			a := a
			approved = &a
			break
		}
	}
	if approved == nil {
		return nil
	}
	what := " It now names no dated copy to restore."
	if c := params["restore_path"]; c != "" {
		what = fmt.Sprintf(" It now restores the dated copy %s", c)
		if d := params["restore_digest"]; d != "" {
			what += ", pinned to " + d
		}
		what += "."
	}
	msg := fmt.Sprintf("the node's answer changed since you approved: you approved %s, and the plan "+
		"this node derives now is %s.%s Nothing was changed. Ask again for a fresh gate.",
		approved.PlanID, planID, what)
	data := map[string]any{
		"door": "run", "reason": refusedPlanChanged, "runbook": rb.ID, "stage": stage,
		"approved_plan": approved.PlanID, "derived_plan": planID,
		"restore_path": params["restore_path"], "restore_digest": params["restore_digest"],
	}
	if l, err := ledger.Open(s.ledgerPath()); err == nil && l != nil {
		l.AppendAs(ledger.KindRefusal, approved.PlanID,
			"run refused: the plan this node derives now is not the one approved", data,
			serviceActor("executor"))
	} else {
		log.Printf("[execute] refused %s (approved %s) and the ledger could not be opened: %v", planID, approved.PlanID, err)
	}
	return map[string]any{
		"error":         msg,
		"reason":        refusedPlanChanged,
		"approved_plan": approved.PlanID,
		"derived_plan":  planID,
	}
}

// sourceMovedRefusal is planMovedRefusal for the upgrade (#1033). There is
// no approval for the plan this run binds, and there IS a live approval for
// this same request whose image was bound to another source or digest: the
// registry's answer moved between the gate and the run.
//
// "This same request" is proved, not assumed. The approval carries the
// source and digest it was bound to, and they count only if binding this
// request with them gives back the approval's own fingerprint. An approval
// for another target, or one whose recorded values do not reproduce its
// fingerprint, is not this request, and the run is refused by RunStage as
// unapproved like any other.
//
// Nothing runs and the approval is left standing; the refusal names both
// values, and asking again mints a gate for the image the node names now.
func (s *server) sourceMovedRefusal(dir string, rb runbook.Runbook, node, planID, fp, stage string,
	params runbook.Params, in planParams) map[string]any {
	// A build the operator asked for binds nothing from the node, so there
	// is no answer of the node's to have moved.
	if in.Source == "build" {
		return nil
	}
	now := time.Now()
	if _, err := approval.Check(dir, planID, fp, node, stage, now); err == nil {
		return nil
	}
	for _, a := range approval.LiveFor(dir, rb.ID, node, stage, now) {
		if a.PlanID == planID {
			continue
		}
		was := in
		was.Source, was.Digest = a.Source, a.Digest
		bound, err := bindRequest(rb, was)
		if err != nil || approval.Fingerprint(rb.ID, node, bound) != a.Fingerprint {
			continue
		}
		approved, derived := sourceWords(a.Source, a.Digest), sourceWords(params["source"], params["digest"])
		msg := fmt.Sprintf("the node's answer changed since you approved: you approved %s, and %s now names %s "+
			"(plan %s, approved as %s). Nothing was changed. Ask again for a fresh gate.",
			approved, in.Target, derived, planID, a.PlanID)
		data := map[string]any{
			"door": "run", "reason": refusedPlanChanged, "runbook": rb.ID, "stage": stage,
			"approved_plan": a.PlanID, "derived_plan": planID,
			"approved_source": a.Source, "approved_digest": a.Digest,
			"derived_source": params["source"], "derived_digest": params["digest"],
		}
		if l, err := ledger.Open(s.ledgerPath()); err == nil && l != nil {
			l.AppendAs(ledger.KindRefusal, a.PlanID,
				"run refused: the image this node names now is not the one approved", data,
				serviceActor("executor"))
		} else {
			log.Printf("[execute] refused %s (approved %s) and the ledger could not be opened: %v", planID, a.PlanID, err)
		}
		return map[string]any{
			"error": msg, "reason": refusedPlanChanged,
			"approved_plan": a.PlanID, "derived_plan": planID,
			"approved_digest": a.Digest, "derived_digest": params["digest"],
		}
	}
	return nil
}

// sourceWords names where an upgrade's image comes from, for a refusal.
func sourceWords(source, digest string) string {
	if source == "official" && digest != "" {
		return "the official image pinned at " + digest
	}
	return "a build from the signed package, with no official image pinned"
}
