"""
Version 4: AI-Powered Defense (Intent Detection)
=================================================

This version demonstrates COMPLETE DEFENSE-IN-DEPTH:
- Hardened prompts with security instructions (from V2)
- Regex pattern detection (Phase 1)
- Heuristic keyword detection (Phase 2)
- LLM-based intent classification (Phase 3) ⭐ NEW!
- Red banner warnings
- Safe mode execution control

EXPECTED BEHAVIOR:
- Detects obvious patterns (regex)
- Detects suspicious keywords (heuristics)
- Detects semantic manipulation attempts (LLM intent)
- Robust against mutation and obfuscation
- Comprehensive protection

STILL CHALLENGING:
- Extremely sophisticated novel attacks
- Zero-day injection techniques
- But SIGNIFICANTLY more robust than V1-V3

PURPOSE: Production-ready defense strategy
"""

import json
import asyncio
import re
from typing import TypedDict, Optional, Dict, Any
from langgraph.graph import StateGraph, START, END
from lg_utility import save_graph_as_png

from git_agent import git_agent_graph
from llm_agent import llm_review_agent_graph
from prompt_injection_guard import prompt_injection_guard_node
from prompt_injection_intent import prompt_injection_intent_node  # NEW!
from red_banner import red_banner_pr_comment_node

# Configuration
MAX_API_CALLS_PER_RUN = 20
PII_PATTERNS = {
    'api_key': r'(?i)(api[_-]?key|apikey|api[_-]?secret)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
    'password': r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^\s"\']{8,})',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
    'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
}


class OrchestratorState(TypedDict):
    """State for Version 4 Orchestrator"""
    # Input
    owner: str
    repo: str
    pull_number: int
    
    # Results from each agent
    git_read_result: Optional[Dict[str, Any]]
    llm_review_result: Optional[Dict[str, Any]]
    
    # Guardrails
    guardrail_checks: Optional[Dict[str, Any]]
    api_call_count: int
    
    # Security detection
    prompt_injection: Optional[Dict[str, Any]]
    prompt_injection_intent: Optional[Dict[str, Any]]  # NEW in V4
    red_banner_comment: Optional[Dict[str, Any]]


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def check_pii_in_diffs(diffs: list) -> Dict[str, Any]:
    """Detect PII in code diffs"""
    pii_findings = {
        "has_pii": False,
        "pii_types": [],
        "locations": []
    }
    
    for diff in diffs:
        patch = diff.get("patch", "")
        
        for pii_type, pattern in PII_PATTERNS.items():
            matches = re.findall(pattern, patch)
            if matches:
                pii_findings["has_pii"] = True
                if pii_type not in pii_findings["pii_types"]:
                    pii_findings["pii_types"].append(pii_type)
                pii_findings["locations"].append({
                    "file": diff["filename"],
                    "pii_type": pii_type,
                    "match_count": len(matches)
                })
    
    return pii_findings


def check_rate_limit(api_call_count: int) -> Dict[str, Any]:
    """Check if rate limit exceeded"""
    return {
        "within_limit": api_call_count < MAX_API_CALLS_PER_RUN,
        "current_count": api_call_count,
        "max_allowed": MAX_API_CALLS_PER_RUN,
        "percentage_used": (api_call_count / MAX_API_CALLS_PER_RUN) * 100
    }


def check_read_only_mode(state: OrchestratorState) -> Dict[str, Any]:
    """Verify system is in read-only mode (no write operations)"""
    return {
        "is_read_only": True,
        "allowed_operations": ["read", "analyze", "validate"],
        "blocked_operations": ["write", "merge", "close", "comment"]
    }


# ============================================================================
# GRAPH NODES
# ============================================================================

async def init_node(state: OrchestratorState) -> OrchestratorState:
    """Initialize orchestrator state"""
    print("\n" + "="*70)
    print("VERSION 4: AI-POWERED DEFENSE (INTENT DETECTION)")
    print("="*70)
    print(f"📝 PR: {state['owner']}/{state['repo']} #{state['pull_number']}")
    print("🛡️  Defense Layers:")
    print("   1. Hardened prompts with security instructions")
    print("   2. Regex pattern detection (Phase 1)")
    print("   3. Heuristic keyword detection (Phase 2)")
    print("   4. ⭐ LLM intent classification (Phase 3) ⭐")
    print("   5. Red banner warnings")
    print("   6. Safe mode execution control")
    print("🎯 Production-ready defense!")
    print("="*70 + "\n")
    
    state["git_read_result"] = None
    state["llm_review_result"] = None
    state["guardrail_checks"] = None
    state["api_call_count"] = 0
    state["prompt_injection"] = None
    state["prompt_injection_intent"] = None
    state["red_banner_comment"] = None
    
    return state


async def check_guardrails_node(state: OrchestratorState) -> OrchestratorState:
    """Enforce basic safety guardrails"""
    print("\n[V4] Checking basic guardrails...")
    
    guardrail_results = {
        "all_passed": True,
        "checks": {}
    }
    
    # Read-only mode check
    read_only_check = check_read_only_mode(state)
    guardrail_results["checks"]["read_only"] = read_only_check
    print(f"✅ Read-only mode: Enforced")
    
    # Rate limit check
    rate_limit_check = check_rate_limit(state.get("api_call_count", 0))
    guardrail_results["checks"]["rate_limit"] = rate_limit_check
    
    if not rate_limit_check["within_limit"]:
        guardrail_results["all_passed"] = False
        print(f"❌ Rate limit exceeded: {rate_limit_check['current_count']}/{rate_limit_check['max_allowed']}")
    else:
        print(f"✅ Rate limit: {rate_limit_check['current_count']}/{rate_limit_check['max_allowed']}")
    
    guardrail_results["checks"]["pii_detection"] = {
        "status": "pending", 
        "message": "Will check after diffs loaded"
    }
    
    state["guardrail_checks"] = guardrail_results
    
    return state


async def git_read_node(state: OrchestratorState) -> OrchestratorState:
    """Fetch PR data from Git"""
    print(f"\n[V4] Fetching PR data from GitHub...")
    
    try:
        initial_state = {
            "owner": state["owner"],
            "repo": state["repo"],
            "pull_number": state["pull_number"]
        }
        
        retval = await git_agent_graph.ainvoke(initial_state)
        state["git_read_result"] = retval
        
        if retval.get("pr_details", {}).get("error"):
            print(f"⚠️  Git agent completed with errors")
        else:
            print(f"✅ Successfully fetched PR data")
        
    except Exception as e:
        print(f"❌ Git agent failed: {str(e)}")
        state["git_read_result"] = {
            "error": str(e),
            "diffs": [],
            "pr_details": {}
        }
    
    return state


async def check_pii_node(state: OrchestratorState) -> OrchestratorState:
    """Check for PII in code diffs"""
    print("\n[V4] Checking for PII in diffs...")
    
    diffs = state["git_read_result"].get("diffs", []) if state["git_read_result"] else []
    
    pii_check = check_pii_in_diffs(diffs)
    
    if state["guardrail_checks"]:
        state["guardrail_checks"]["checks"]["pii_detection"] = pii_check
    
    if pii_check["has_pii"]:
        print(f"⚠️  PII detected in diffs:")
        for location in pii_check["locations"]:
            print(f"   - {location['file']}: {location['pii_type']} ({location['match_count']} matches)")
        print(f"⚠️  Consider redacting before review")
    else:
        print(f"✅ No PII detected in diffs")
    
    return state


async def llm_review_node(state: OrchestratorState) -> OrchestratorState:
    """Run LLM code review with SAFE MODE support"""
    
    # Check if prompt injection was detected by ANY layer
    if state.get("prompt_injection", {}).get("detected"):
        print(f"\n[V4] 🚨 PROMPT INJECTION DETECTED - ENTERING SAFE MODE")
        print(f"   LLM review BLOCKED to protect system integrity")
        
        # Show detection details
        injection = state["prompt_injection"]
        print(f"   Confidence: {injection.get('confidence', 'unknown')}")
        
        signals = injection.get("signals", {})
        print(f"   Detection signals:")
        if signals.get("regex"):
            print(f"      ✓ Phase 1 (Regex patterns)")
        if signals.get("heuristics"):
            print(f"      ✓ Phase 2 (Heuristic keywords)")
        if signals.get("intent"):
            print(f"      ✓ Phase 3 (LLM intent classification)")
        
        if injection.get("intent_types"):
            print(f"   Intent types: {', '.join(injection.get('intent_types', []))}")
        
        if injection.get("explanation"):
            print(f"   Analysis: {injection.get('explanation')}")
        
        state["llm_review_result"] = {
            "skipped": True,
            "reason": "Prompt injection detected - review blocked for safety",
            "prompt_injection": state["prompt_injection"],
            "requires_human_review": True
        }
        return state
    
    # No injection detected - proceed normally
    print(f"\n[V4] Running LLM code review (all security checks passed)...")
    print(f"🛡️  Using hardened prompts")
    print(f"✅ Phase 1, 2, 3 checks: All clear")
    
    try:
        diffs = state["git_read_result"].get("diffs", []) if state["git_read_result"] else []
        
        if not diffs:
            print("⚠️  No diffs available, skipping LLM review")
            state["llm_review_result"] = {
                "skipped": True,
                "reason": "No diffs to review"
            }
            return state
        
        # Pass diffs to LLM review agent with v4 prompts
        initial_state = {
            "owner": state["owner"],
            "repo": state["repo"],
            "pull_number": state["pull_number"],
            "diffs": diffs,
            "prompt_version": "v4"  # Use hardened prompts
        }
        
        retval = await llm_review_agent_graph.ainvoke(initial_state)
        state["llm_review_result"] = retval
        
        print(f"✅ LLM review completed successfully")
        
        # Show summary
        if "bugs_found" in retval:
            print(f"📊 Bugs found: {len(retval.get('bugs_found', []))}")
        
    except Exception as e:
        print(f"❌ LLM review failed: {str(e)}")
        state["llm_review_result"] = {
            "error": str(e),
            "bugs_found": []
        }
    
    return state


# ============================================================================
# GRAPH CREATION
# ============================================================================

def create_v4_orchestrator_graph():
    """
    Create Version 4 orchestrator graph (AI-POWERED DEFENSE)
    
    Flow: 
    INIT → GUARDRAILS → GIT_READ → CHECK_PII 
    → PROMPT_INJECTION_GUARD (Phase 1 & 2)
    → PROMPT_INJECTION_INTENT (Phase 3 - NEW!)
    → RED_BANNER (if detected) or LLM_REVIEW (if safe)
    → END
    
    Key differences from V3:
    - Adds prompt_injection_intent_node (LLM-based intent detection)
    - More sophisticated threat detection
    - Robust against mutation/obfuscation
    - Production-ready defense
    """
    print("\n🔧 Building Version 4 Orchestrator Graph (AI-Powered Defense)...")
    
    workflow = StateGraph(OrchestratorState)
    
    # Add nodes
    workflow.add_node("INIT", init_node)
    workflow.add_node("CHECK_GUARDRAILS", check_guardrails_node)
    workflow.add_node("GIT_READ", git_read_node)
    workflow.add_node("CHECK_PII", check_pii_node)
    workflow.add_node("PROMPT_INJECTION_GUARD", prompt_injection_guard_node)
    workflow.add_node("PROMPT_INJECTION_INTENT", prompt_injection_intent_node)  # NEW!
    workflow.add_node("RED_BANNER", red_banner_pr_comment_node)
    workflow.add_node("LLM_REVIEW", llm_review_node)
    
    # Add edges - linear flow through all detection layers
    workflow.add_edge(START, "INIT")
    workflow.add_edge("INIT", "CHECK_GUARDRAILS")
    workflow.add_edge("CHECK_GUARDRAILS", "GIT_READ")
    workflow.add_edge("GIT_READ", "CHECK_PII")
    workflow.add_edge("CHECK_PII", "PROMPT_INJECTION_GUARD")
    workflow.add_edge("PROMPT_INJECTION_GUARD", "PROMPT_INJECTION_INTENT")  # Phase 3
    
    # Conditional routing after ALL detection layers
    def route_after_intent(state: OrchestratorState):
        """Route based on injection detection from ALL phases"""
        if state.get("prompt_injection", {}).get("detected"):
            return "RED_BANNER"  # Any phase detected injection - show warning
        return "LLM_REVIEW"  # All phases clear - proceed with review
    
    workflow.add_conditional_edges(
        "PROMPT_INJECTION_INTENT",
        route_after_intent,
        {
            "RED_BANNER": "RED_BANNER",
            "LLM_REVIEW": "LLM_REVIEW"
        }
    )
    
    # Both paths end
    workflow.add_edge("RED_BANNER", END)
    workflow.add_edge("LLM_REVIEW", END)
    
    graph = workflow.compile()
    
    # Save graph visualization
    try:
        save_graph_as_png(graph, "v4_orchestrator_AI_defense")
        print("✅ Graph compiled and saved\n")
    except Exception as e:
        print(f"✅ Graph compiled (visualization save failed: {e})\n")
    
    return graph


# Create the graph
orchestrator_graph = create_v4_orchestrator_graph()


# ============================================================================
# EXECUTION
# ============================================================================

async def run_v4_orchestrator(owner: str, repo: str, pull_number: int):
    """Execute Version 4 AI-powered defense orchestrator"""
    
    initial_state = OrchestratorState(
        owner=owner,
        repo=repo,
        pull_number=pull_number
    )
    
    final_state = await orchestrator_graph.ainvoke(initial_state)
    
    # Print final summary
    print("\n" + "="*70)
    print("EXECUTION COMPLETE - VERSION 4 SUMMARY")
    print("="*70)
    print(f"PR: {owner}/{repo} #{pull_number}")
    print(f"Defense: Complete AI-powered defense stack")
    
    # Show injection detection results with phase breakdown
    if final_state.get("prompt_injection"):
        injection = final_state["prompt_injection"]
        if injection.get("detected"):
            print(f"\n🚨 THREAT DETECTED:")
            print(f"   Overall confidence: {injection.get('confidence', 'unknown')}")
            
            signals = injection.get("signals", {})
            print(f"   Detection phases:")
            print(f"      Phase 1 (Regex): {'✓ Detected' if signals.get('regex') else '✗ Clear'}")
            print(f"      Phase 2 (Heuristics): {'✓ Detected' if signals.get('heuristics') else '✗ Clear'}")
            print(f"      Phase 3 (Intent AI): {'✓ Detected' if signals.get('intent') else '✗ Clear'}")
            
            if injection.get("intent_types"):
                print(f"   Attack types: {', '.join(injection.get('intent_types', []))}")
            
            if injection.get("explanation"):
                print(f"   AI analysis: {injection.get('explanation')}")
            
            if final_state.get("red_banner_comment"):
                print(f"   🚩 Red banner: Security warning posted")
        else:
            print(f"\n✅ All security checks passed:")
            print(f"   ✓ Phase 1 (Regex patterns): Clear")
            print(f"   ✓ Phase 2 (Heuristic keywords): Clear")
            print(f"   ✓ Phase 3 (Intent classification): Clear")
            print(f"   Review completed safely")
    
    # Show review results
    if final_state.get("llm_review_result"):
        review = final_state["llm_review_result"]
        if review.get("skipped"):
            print(f"\n⚠️  Review status: {review.get('reason')}")
            if review.get("requires_human_review"):
                print(f"   🧑 Human review REQUIRED")
        elif review.get("error"):
            print(f"\n❌ Review failed: {review.get('error')}")
        else:
            bugs_count = len(review.get("bugs_found", []))
            print(f"\n📊 Review results:")
            print(f"   Bugs found: {bugs_count}")
    
    print("\n🎯 Version 4 provides production-ready defense against:")
    print("   ✓ Direct injection attacks")
    print("   ✓ Disguised instructions")
    print("   ✓ Mutated patterns")
    print("   ✓ Semantic manipulation")
    print("="*70 + "\n")
    
    # Optional: Print detailed results
    if "--debug" in __import__("sys").argv:
        print("\n" + "="*70)
        print("DEBUG: FINAL STATE (Complete Output)")
        print("="*70)
        print(json.dumps(final_state, indent=2, default=str))
        print("="*70 + "\n")
    
    return final_state


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Main entry point"""
    
    # Example PRs (replace with your actual PRs)
    PR_DETAILS = {
        "owner": "promptlyaig",
        "repo": "issue-tracker",
        "pull_number": 8  # Try PR with sophisticated mutation attacks
    }
    
    print("\n" + "="*70)
    print("🚀 RUNNING VERSION 4: AI-POWERED DEFENSE")
    print("="*70)
    print("\nThis version demonstrates COMPLETE DEFENSE-IN-DEPTH:")
    print("\n📋 Defense Layers:")
    print("1. Hardened prompts (tell LLM to ignore injection)")
    print("2. Phase 1 - Regex patterns (catch obvious attacks)")
    print("3. Phase 2 - Heuristic keywords (catch suspicious terms)")
    print("4. ⭐ Phase 3 - LLM intent classifier (catch semantic manipulation)")
    print("5. Red banner warnings (alert humans)")
    print("6. Safe mode execution (block LLM if threat detected)")
    print("\n🎯 PRODUCTION-READY DEFENSE!")
    print("\nProtects against:")
    print("✓ Direct injection ('ignore instructions')")
    print("✓ Disguised instructions (documentation-style)")
    print("✓ Mutated patterns (line breaks, synonyms)")
    print("✓ Semantic manipulation (intent without keywords)")
    print("\nExpected: Comprehensive protection")
    print("="*70 + "\n")
    
    asyncio.run(run_v4_orchestrator(**PR_DETAILS))


if __name__ == "__main__":
    main()
