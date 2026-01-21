"""
Version 1: Vulnerable Orchestrator (Baseline)
==============================================

This version demonstrates the PROBLEM:
- Uses basic prompts with NO security instructions
- No prompt injection detection
- Agent can be manipulated by malicious code comments

EXPECTED BEHAVIOR:
- Will be fooled by prompt injection attacks
- May suppress bug reports if instructed by code
- May produce false positive reviews

PURPOSE: Educational - shows why defense is needed
"""

import json
import asyncio
import re
from typing import TypedDict, Optional, Dict, Any
from langgraph.graph import StateGraph, START, END
from lg_utility import save_graph_as_png

from git_agent import git_agent_graph
from llm_agent import llm_review_agent_graph

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
    """State for Version 1 Orchestrator"""
    # Input
    owner: str
    repo: str
    pull_number: int
    
    # Results from each agent
    git_read_result: Optional[Dict[str, Any]]
    llm_review_result: Optional[Dict[str, Any]]
    
    # Guardrails (basic only)
    guardrail_checks: Optional[Dict[str, Any]]
    api_call_count: int


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
    print("VERSION 1: VULNERABLE ORCHESTRATOR (BASELINE)")
    print("="*70)
    print(f"📝 PR: {state['owner']}/{state['repo']} #{state['pull_number']}")
    print("⚠️  WARNING: This version has NO prompt injection defense!")
    print("="*70 + "\n")
    
    state["git_read_result"] = None
    state["llm_review_result"] = None
    state["guardrail_checks"] = None
    state["api_call_count"] = 0
    
    return state


async def check_guardrails_node(state: OrchestratorState) -> OrchestratorState:
    """Enforce basic safety guardrails"""
    print("\n[V1] Checking basic guardrails...")
    
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
    print(f"\n[V1] Fetching PR data from GitHub...")
    
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
    print("\n[V1] Checking for PII in diffs...")
    
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
    """Run LLM code review (VULNERABLE - no injection defense)"""
    print(f"\n[V1] Running LLM code review (VULNERABLE)...")
    print(f"⚠️  Using basic prompts with NO security instructions")
    print(f"⚠️  Susceptible to prompt injection attacks!")
    
    try:
        diffs = state["git_read_result"].get("diffs", []) if state["git_read_result"] else []
        
        if not diffs:
            print("⚠️  No diffs available, skipping LLM review")
            state["llm_review_result"] = {
                "skipped": True,
                "reason": "No diffs to review"
            }
            return state
        
        # Pass diffs to LLM review agent
        # NOTE: llm_agent will use v1 prompts (no security)
        initial_state = {
            "owner": state["owner"],
            "repo": state["repo"],
            "pull_number": state["pull_number"],
            "diffs": diffs
        }
        
        retval = await llm_review_agent_graph.ainvoke(initial_state)
        state["llm_review_result"] = retval
        
        print(f"✅ LLM review completed")
        
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

def create_v1_orchestrator_graph():
    """
    Create Version 1 orchestrator graph (VULNERABLE)
    
    Flow: INIT → GUARDRAILS → GIT_READ → CHECK_PII → LLM_REVIEW → END
    
    Note: No prompt injection detection!
    """
    print("\n🔧 Building Version 1 Orchestrator Graph (Vulnerable)...")
    
    workflow = StateGraph(OrchestratorState)
    
    # Add nodes
    workflow.add_node("INIT", init_node)
    workflow.add_node("CHECK_GUARDRAILS", check_guardrails_node)
    workflow.add_node("GIT_READ", git_read_node)
    workflow.add_node("CHECK_PII", check_pii_node)
    workflow.add_node("LLM_REVIEW", llm_review_node)
    
    # Add edges (simple linear flow)
    workflow.add_edge(START, "INIT")
    workflow.add_edge("INIT", "CHECK_GUARDRAILS")
    workflow.add_edge("CHECK_GUARDRAILS", "GIT_READ")
    workflow.add_edge("GIT_READ", "CHECK_PII")
    workflow.add_edge("CHECK_PII", "LLM_REVIEW")
    workflow.add_edge("LLM_REVIEW", END)
    
    graph = workflow.compile()
    
    # Save graph visualization
    try:
        save_graph_as_png(graph, "v1_orchestrator_vulnerable")
        print("✅ Graph compiled and saved\n")
    except Exception as e:
        print(f"✅ Graph compiled (visualization save failed: {e})\n")
    
    return graph


# Create the graph
orchestrator_graph = create_v1_orchestrator_graph()


# ============================================================================
# EXECUTION
# ============================================================================

async def run_v1_orchestrator(owner: str, repo: str, pull_number: int):
    """Execute Version 1 vulnerable orchestrator"""
    
    initial_state = OrchestratorState(
        owner=owner,
        repo=repo,
        pull_number=pull_number
    )
    
    final_state = await orchestrator_graph.ainvoke(initial_state)
    
    # Print final summary
    print("\n" + "="*70)
    print("EXECUTION COMPLETE - VERSION 1 SUMMARY")
    print("="*70)
    print(f"PR: {owner}/{repo} #{pull_number}")
    
    if final_state.get("llm_review_result"):
        review = final_state["llm_review_result"]
        if review.get("skipped"):
            print(f"⚠️  Review skipped: {review.get('reason')}")
        elif review.get("error"):
            print(f"❌ Review failed: {review.get('error')}")
        else:
            bugs_count = len(review.get("bugs_found", []))
            print(f"📊 Bugs found: {bugs_count}")
    
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
        "pull_number": 5  # Change this to test different PRs
    }
    
    print("\n" + "="*70)
    print("🚀 RUNNING VERSION 1: VULNERABLE ORCHESTRATOR")
    print("="*70)
    print("\nThis version demonstrates the PROBLEM:")
    print("- Basic prompts with NO security instructions")
    print("- NO prompt injection detection")
    print("- Agent CAN be manipulated by malicious code\n")
    print("Expected: Agent will be fooled by injection attacks")
    print("="*70 + "\n")
    
    asyncio.run(run_v1_orchestrator(**PR_DETAILS))


if __name__ == "__main__":
    main()
