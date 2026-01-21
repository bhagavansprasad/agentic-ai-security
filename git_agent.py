import os
from fastmcp import Client
import json
from typing import TypedDict, Optional, List, Dict, Any
from langgraph.graph import StateGraph, START, END
import asyncio
from lg_utility import save_graph_as_png

MAX_FILES_THRESHOLD = 50
CODE_EXTENSIONS = {'py', 'js', 'java', 'go', 'cpp'}

async def retry_with_backoff(func, max_retries=3, initial_delay=1):
    """
    Retry a function with exponential backoff
    """
    for attempt in range(max_retries):
        try:
            return await func()
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            delay = initial_delay * (2 ** attempt)
            print(f"⚠️  Attempt {attempt + 1} failed: {str(e)}")
            print(f"   Retrying in {delay}s...")
            await asyncio.sleep(delay)

class GitAgentState(TypedDict):
    # Input (required)
    owner: str
    repo: str
    pull_number: int
    client: Optional[Any]
    
    # Output (structured data for other agents)
    pr_details: Optional[Dict[str, Any]]
    changed_files: Optional[List[Dict[str, Any]]]
    diffs: Optional[List[Dict[str, Any]]]
    
    # Internal state
    has_valid_files: bool
    validation_result: Optional[Dict[str, Any]]

async def call_mcp_tool(client, tool_name: str, arguments: dict = None) -> dict:
    """Helper to call MCP tools"""
    result = await client.call_tool(tool_name, arguments)
    content_text = result.content[0].text

    return json.loads(content_text) if content_text else {}


async def connect_mcp_node(state: GitAgentState) -> GitAgentState:
    """Connect to MCP server"""
    print(f"\n[NODE 0] Connecting to GitHub MCP...")
    
    GITHUB_MCP_SERVER_URL = os.getenv("GITHUB_MCP_SERVER_URL")
    client = Client(GITHUB_MCP_SERVER_URL)
    
    # Connect and store in state
    await client.__aenter__()
    
    state["client"] = client
    
    print(f"✅ Connected to MCP")
    
    return state


async def init_state_node(state: GitAgentState) -> GitAgentState:
    """
    Node 0: Initialize state with default values
    """
    print("\n[NODE 0] Initializing Git Agent state...")
    
    # Create MCP client if not provided by orchestrator
    if not state.get("client"):
        print("   Creating MCP client...")
        GITHUB_MCP_SERVER_URL = os.getenv("GITHUB_MCP_SERVER_URL")
        client = Client(GITHUB_MCP_SERVER_URL)
        await client.__aenter__()
        state["client"] = client
        print("   ✅ MCP client created")
    
    # Initialize all output fields with default values
    state["pr_details"] = {}
    state["changed_files"] = []
    state["diffs"] = []
    state["has_valid_files"] = False
    state["validation_result"] = None
    
    print(f"✅ State initialized for {state['owner']}/{state['repo']} PR #{state['pull_number']}")
    
    return state

async def fetch_pr_details_node(state: GitAgentState) -> GitAgentState:
    """Fetch PR details using GITHUB_GET_A_PULL_REQUEST"""
    print(f"\n[NODE 1] Fetching PR details for #{state['pull_number']}...")
    
    try:
        async def fetch_operation():
            tool_name = "GITHUB_GET_A_PULL_REQUEST"
            args = {"owner": state["owner"],
                    "repo": state["repo"],
                    "pull_number": state["pull_number"]}
            
            response = await call_mcp_tool(state['client'], tool_name, args)
            return response
        
        response = await retry_with_backoff(fetch_operation, max_retries=3)
        pr_data = response["data"]
        
        state["pr_details"] = {
            "number": state["pull_number"],
            "title": pr_data.get("title"),
            "body": pr_data.get("body"),
            "state": pr_data.get("state"),
            "diff_url": pr_data.get("diff_url"),
            "patch_url": pr_data.get("patch_url"),
            "additions": pr_data.get("additions"),
            "deletions": pr_data.get("deletions"),
            "changed_files": pr_data.get("changed_files"),
            "html_url": pr_data.get("html_url")
        }
        print(f"✅ PR details fetched successfully")
        
        # ===== DEBUG: Print pr_details structure =====
        print("\n" + "-"*60)
        print("DEBUG: PR_DETAILS STRUCTURE")
        print("-"*60)
        print(json.dumps(state["pr_details"], indent=2, default=str))
        print("-"*60 + "\n")
        # =============================================
        
    except Exception as e:
        print(f"❌ Failed to fetch PR details after retries: {str(e)}")
        state["pr_details"] = {
            "error": str(e),
            "number": state["pull_number"]
        }
    
    return state    

async def fetch_pr_files_node(state: GitAgentState) -> GitAgentState:
    """Fetch changed files using GITHUB_LIST_PULL_REQUESTS_FILES"""
    print(f"\n[NODE 2] Fetching changed files for PR #{state['pull_number']}...")
    
    try:
        async def fetch_operation():
            tool_name = "GITHUB_LIST_PULL_REQUESTS_FILES"
            args = {
                "owner": state["owner"],
                "repo": state["repo"],
                "pull_number": state["pull_number"]
            }
            
            response = await call_mcp_tool(state['client'], tool_name, args)
            return response
        
        response = await retry_with_backoff(fetch_operation, max_retries=3)
        files = response["data"]["details"]
        
        state["changed_files"] = []
        for file in files:
            state["changed_files"].append({
                "filename": file["filename"],
                "status": file["status"],
                "additions": file["additions"],
                "deletions": file["deletions"],
                "changes": file["changes"],
                "patch": file.get("patch", "")
            })
        
        print(f"✅ Found {len(state['changed_files'])} changed files")
        
        # ===== DEBUG: Print changed_files structure (first file only) =====
        print("\n" + "-"*60)
        print("DEBUG: CHANGED_FILES STRUCTURE (Sample - First File)")
        print("-"*60)
        if state["changed_files"]:
            print(json.dumps(state["changed_files"][0], indent=2, default=str))
        print(f"Total files: {len(state['changed_files'])}")
        print("-"*60 + "\n")
        # =================================================================
        
    except Exception as e:
        print(f"❌ Failed to fetch PR files after retries: {str(e)}")
        state["changed_files"] = []
    
    return state

async def extract_diffs_node(state: GitAgentState) -> GitAgentState:
    """Extract and structure diff data from changed files"""
    print(f"\n[NODE 3] Extracting and structuring diffs...")

    try:
        state["diffs"] = []
        
        for file in state["changed_files"]:
            if not file.get("patch"):
                continue
            
            filename = file["filename"]
            ext = filename.split(".")[-1] if "." in filename else "unknown"
            
            structured_diff = {
                "filename": filename,
                "status": file["status"],
                "language": ext,
                "additions": file["additions"],
                "deletions": file["deletions"],
                "patch": file["patch"]
            }
            
            state["diffs"].append(structured_diff)
        
        state["has_valid_files"] = len(state["diffs"]) > 0
        
        print(f"✅ Extracted {len(state['diffs'])} structured diffs")
        
        # ===== DEBUG: Print diffs structure (first diff only) =====
        print("\n" + "-"*60)
        print("DEBUG: DIFFS STRUCTURE (Sample - First Diff)")
        print("-"*60)
        if state["diffs"]:
            # Show first diff with truncated patch
            sample_diff = state["diffs"][0].copy()
            if len(sample_diff.get("patch", "")) > 200:
                sample_diff["patch"] = sample_diff["patch"][:200] + "... [truncated]"
            print(json.dumps(sample_diff, indent=2, default=str))
        print(f"Total diffs: {len(state['diffs'])}")
        print("-"*60 + "\n")
        # ===========================================================
        
    except Exception as e:
        print(f"❌ Failed to extract diffs: {str(e)}")
        state["diffs"] = []
        state["has_valid_files"] = False
    
    return state

async def validate_pr_suitability_node(state: GitAgentState) -> GitAgentState:
    """
    Validate if PR is suitable for automated review (ADAPTABILITY)
    """
    print(f"\n[NODE 4] Validating PR suitability...")
    
    validation = {
        "is_suitable": True,
        "warnings": [],
        "reasons": []
    }
    
    if len(state["diffs"]) == 0:
        validation["is_suitable"] = False
        validation["reasons"].append("No code diffs found (only binary/deleted files)")
        print("⚠️  No reviewable code changes detected")
    
    elif len(state["diffs"]) > MAX_FILES_THRESHOLD:
        validation["warnings"].append(f"Large PR: {len(state['diffs'])} files (consider chunking)")
        print(f"⚠️  Large PR detected: {len(state['diffs'])} files")
    
    code_files = [d for d in state["diffs"] if d["language"] in CODE_EXTENSIONS]
    
    if len(code_files) == 0 and len(state["diffs"]) > 0:
        validation["warnings"].append("No code files detected (only config/docs)")
        print("⚠️  Only configuration/documentation files found")
    
    empty_patches = [d for d in state["diffs"] if not d.get("patch") or len(d["patch"]) < 10]
    if len(empty_patches) > 0:
        validation["warnings"].append(f"{len(empty_patches)} files have minimal/no changes")
    
    state["validation_result"] = validation
    
    if validation["is_suitable"]:
        print(f"✅ PR is suitable for review ({len(code_files)} code files)")
    else:
        print(f"❌ PR validation failed: {', '.join(validation['reasons'])}")
    
    if validation["warnings"]:
        for warning in validation["warnings"]:
            print(f"⚠️  {warning}")
    
    return state

def create_git_agent_graph():
    """
    Build the Git Agent LangGraph workflow (Read-Only Mode)
    
    Graph structure:
    START → CONNECT_MCP → INIT_STATE → FETCH_PR_DETAILS → FETCH_PR_FILES → EXTRACT_DIFFS → VALIDATE_SUITABILITY → END
    """
    print("\n🔧 Building Git Agent Graph...")
    
    workflow = StateGraph(GitAgentState)
    
    workflow.add_node("CONNECT_MCP", connect_mcp_node)
    workflow.add_node("INIT_STATE", init_state_node)
    workflow.add_node("FETCH_PR_DETAILS", fetch_pr_details_node)
    workflow.add_node("FETCH_PR_FILES", fetch_pr_files_node)
    workflow.add_node("EXTRACT_DIFFS", extract_diffs_node)
    workflow.add_node("VALIDATE_SUITABILITY", validate_pr_suitability_node)
    
    workflow.add_edge(START, "CONNECT_MCP")
    workflow.add_edge("CONNECT_MCP", "INIT_STATE")
    workflow.add_edge("INIT_STATE", "FETCH_PR_DETAILS")
    workflow.add_edge("FETCH_PR_DETAILS", "FETCH_PR_FILES")
    workflow.add_edge("FETCH_PR_FILES", "EXTRACT_DIFFS")
    workflow.add_edge("EXTRACT_DIFFS", "VALIDATE_SUITABILITY")
    workflow.add_edge("VALIDATE_SUITABILITY", END)
    
    app = workflow.compile()
    
    save_graph_as_png(app, "git_agent")
    print("✅ Graph compiled successfully\n")
    
    return app


async def run_git_agent(
    app,
    owner: str,
    repo: str,
    pull_number: int,
    client  # Add client parameter
):
    print("="*70)
    print("GIT AGENT EXECUTION")
    print("="*70)
    
    # Initialize state
    initial_state = GitAgentState(
        owner=owner,
        repo=repo,
        pull_number=pull_number,
        client=client
    )
    
    # Execute graph
    final_state = await app.ainvoke(initial_state)
    
    # Print summary
    print("\n" + "="*70)
    print("WORKFLOW COMPLETE - GIT AGENT SUMMARY")
    print("="*70)
    print(f"PR Number: #{final_state['pull_number']}")
    # print(f"PR Title: {final_state['pr_details']['title']}")
    # print(f"Files Changed: {len(final_state['changed_files'])}")
    print(f"Diffs Extracted: {len(final_state['diffs'])}")
    
    print("="*70)
    print("\n✅ Structured data ready for LLM Review Agent, Jira Agent, etc.")
    
    return final_state

git_agent_graph = create_git_agent_graph()

def main():
    """Main entry point for testing with actual MCP client"""
    
    GITHUB_MCP_SERVER_URL = os.getenv("GITHUB_MCP_SERVER_URL")
    PR_NUMBER = 1
    
    async def test_with_mcp():
        client = Client(GITHUB_MCP_SERVER_URL)
        
        async with client:
            # Test with issue-tracker PR #1
            await run_git_agent(
                app=git_agent_graph,
                owner="promptlyaig",
                repo="issue-tracker",
                pull_number=PR_NUMBER,
                client=client,
            )
    
    asyncio.run(test_with_mcp())
    

if __name__ == "__main__":
    main()