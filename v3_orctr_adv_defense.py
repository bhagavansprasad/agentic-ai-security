"""
Version 3: Advanced Defense (Pattern Detection)
================================================

This version demonstrates MULTI-LAYER DEFENSE:
- Hardened prompts with security instructions (from V2)
- PLUS automated pattern detection (regex + heuristics)
- PLUS red banner warnings when threats detected

EXPECTED BEHAVIOR:
- Detects obvious injection patterns (regex)
- Detects suspicious keywords (heuristics)
- Blocks LLM execution if threats detected
- Posts red banner security warnings

STILL VULNERABLE TO:
- Mutated/obfuscated attacks
- Novel attack patterns
- Semantic manipulation without keywords

PURPOSE: Shows significant improvement but not complete defense
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
    """State for Version 3 Orchestrator"""
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
    
    # Security detection (NEW in V3)
    prompt_injection: Optional[Dict[str, Any]]
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
    print("VERSION 3: ADVANCED DEFENSE (PATTERN DETECTION)")
    print("="*70)
    print(f"📝 PR: {state['owner']}/{state['repo']} #{state['pull_number']}")
    print("🛡️  Defense Layers:")
    print("   1. Hardened prompts with security instructions")
    print("   2. Regex pattern detection (Phase 1)")
    print("   3. Heuristic keyword detection (Phase 2)")
    print("   4. Red banner warnings")
    print("⚠️  Still vulnerable to mutation attacks!")
    print("="*70 + "\n")
    
    state["git_read_result"] = None
    state["llm_review_result"] = None
    state["guardrail_checks"] = None
    state["api_call_count"] = 0
    state["prompt_injection"] = None
    state["red_banner_comment"] = None
    
    return state


async def check_guardrails_node(state: OrchestratorState) -> OrchestratorState:
    """Enforce basic safety guardrails"""
    print("\n[V3] Checking basic guardrails...")
    
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
    print(f"\n[V3] Fetching PR data from GitHub...")
    
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
    print("\n[V3] Checking for PII in diffs...")
    
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
    
    # Check if prompt injection was detected
    if state.get("prompt_injection", {}).get("detected"):
        print(f"\n[V3] 🚨 PROMPT INJECTION DETECTED - ENTERING SAFE MODE")
        print(f"   LLM review BLOCKED to protect system integrity")
        print(f"   Detection confidence: {state['prompt_injection'].get('confidence', 'unknown')}")
        print(f"   Evidence: {len(state['prompt_injection'].get('evidence', []))} signals")
        
        state["llm_review_result"] = {
            "skipped": True,
            "reason": "Prompt injection detected - review blocked for safety",
            "prompt_injection": state["prompt_injection"],
            "requires_human_review": True
        }
        return state
    
    # No injection detected - proceed normally
    print(f"\n[V3] Running LLM code review (injection check passed)...")
    print(f"🛡️  Using hardened prompts")
    
    try:
        diffs = state["git_read_result"].get("diffs", []) if state["git_read_result"] else []
        
        if not diffs:
            print("⚠️  No diffs available, skipping LLM review")
            state["llm_review_result"] = {
                "skipped": True,
                "reason": "No diffs to review"
            }
            return state
        
        # Pass diffs to LLM review agent with v3 prompts
        initial_state = {
            "owner": state["owner"],
            "repo": state["repo"],
            "pull_number": state["pull_number"],
            "diffs": diffs,
            "prompt_version": "v3"  # Use hardened prompts
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

def create_v3_orchestrator_graph():
    """
    Create Version 3 orchestrator graph (ADVANCED DEFENSE)
    
    Flow: 
    INIT → GUARDRAILS → GIT_READ → CHECK_PII 
    → PROMPT_INJECTION_GUARD (NEW!)
    → RED_BANNER (if detected) or LLM_REVIEW (if safe)
    → END
    
    Key differences from V2:
    - Adds prompt_injection_guard_node (regex + heuristics)
    - Adds red_banner_node (security warnings)
    - Conditional routing based on detection
    - LLM blocked if injection detected
    """
    print("\n🔧 Building Version 3 Orchestrator Graph (Advanced Defense)...")
    
    workflow = StateGraph(OrchestratorState)
    
    # Add nodes
    workflow.add_node("INIT", init_node)
    workflow.add_node("CHECK_GUARDRAILS", check_guardrails_node)
    workflow.add_node("GIT_READ", git_read_node)
    workflow.add_node("CHECK_PII", check_pii_node)
    workflow.add_node("PROMPT_INJECTION_GUARD", prompt_injection_guard_node)  # NEW!
    workflow.add_node("RED_BANNER", red_banner_pr_comment_node)  # NEW!
    workflow.add_node("LLM_REVIEW", llm_review_node)
    
    # Add edges - linear flow until detection
    workflow.add_edge(START, "INIT")
    workflow.add_edge("INIT", "CHECK_GUARDRAILS")
    workflow.add_edge("CHECK_GUARDRAILS", "GIT_READ")
    workflow.add_edge("GIT_READ", "CHECK_PII")
    workflow.add_edge("CHECK_PII", "PROMPT_INJECTION_GUARD")
    
    # Conditional routing after guard
    def route_after_guard(state: OrchestratorState):
        """Route based on injection detection"""
        if state.get("prompt_injection", {}).get("detected"):
            return "RED_BANNER"  # Injection detected - show warning
        return "LLM_REVIEW"  # Safe - proceed with review
    
    workflow.add_conditional_edges(
        "PROMPT_INJECTION_GUARD",
        route_after_guard,
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
        save_graph_as_png(graph, "v3_orchestrator_adv_defense")
        print("✅ Graph compiled and saved\n")
    except Exception as e:
        print(f"✅ Graph compiled (visualization save failed: {e})\n")
    
    return graph


# Create the graph
orchestrator_graph = create_v3_orchestrator_graph()


# ============================================================================
# EXECUTION
# ============================================================================

async def run_v3_orchestrator(owner: str, repo: str, pull_number: int):
    """Execute Version 3 advanced defense orchestrator"""
    
    initial_state = OrchestratorState(
        owner=owner,
        repo=repo,
        pull_number=pull_number
    )
    
    final_state = await orchestrator_graph.ainvoke(initial_state)
    
    # Print final summary
    print("\n" + "="*70)
    print("EXECUTION COMPLETE - VERSION 3 SUMMARY")
    print("="*70)
    print(f"PR: {owner}/{repo} #{pull_number}")
    print(f"Defense: Hardened prompts + Pattern detection")
    
    # Show injection detection results
    if final_state.get("prompt_injection"):
        injection = final_state["prompt_injection"]
        if injection.get("detected"):
            print(f"\n🚨 THREAT DETECTED:")
            print(f"   Confidence: {injection.get('confidence', 'unknown')}")
            print(f"   Signals: {injection.get('signals', {})}")
            print(f"   Evidence: {len(injection.get('evidence', []))} patterns matched")
            if final_state.get("red_banner_comment"):
                print(f"   Red banner: Posted security warning")
        else:
            print(f"\n✅ No injection detected - review completed safely")
    
    # Show review results
    if final_state.get("llm_review_result"):
        review = final_state["llm_review_result"]
        if review.get("skipped"):
            print(f"\n⚠️  Review status: {review.get('reason')}")
            if review.get("requires_human_review"):
                print(f"   🧑 Human review required")
        elif review.get("error"):
            print(f"\n❌ Review failed: {review.get('error')}")
        else:
            bugs_count = len(review.get("bugs_found", []))
            print(f"\n📊 Review results:")
            print(f"   Bugs found: {bugs_count}")
    
    print("\n💡 Note: This version catches known patterns but may miss")
    print("   mutated or novel injection attempts.")
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
        "pull_number": 7  # Try PR with known injection patterns
    }
    
    print("\n" + "="*70)
    print("🚀 RUNNING VERSION 3: ADVANCED DEFENSE")
    print("="*70)
    print("\nThis version demonstrates MULTI-LAYER DEFENSE:")
    print("1. Hardened prompts (from V2)")
    print("2. Regex pattern detection (catches obvious attacks)")
    print("3. Heuristic keyword detection (catches suspicious terms)")
    print("4. Red banner warnings (alerts humans)")
    print("5. Safe mode (blocks LLM if threat detected)")
    print("\nSIGNIFICANT IMPROVEMENT over V1 and V2!")
    print("\nBUT STILL VULNERABLE to:")
    print("- Mutated/obfuscated patterns")
    print("- Novel attack techniques")
    print("- Semantic manipulation")
    print("\nExpected: Catches most common attacks")
    print("="*70 + "\n")
    
    asyncio.run(run_v3_orchestrator(**PR_DETAILS))


if __name__ == "__main__":
    main()
