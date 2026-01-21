import os
from typing import TypedDict, Optional, List, Dict, Any
from langgraph.graph import StateGraph, START, END
import asyncio
import google.generativeai as genai
import json
import re
from lg_utility import save_graph_as_png

# from llm_agent_prompts_v1 import (
#     create_analysis_prompt, 
#     REVIEW_COMMENT_GENERATION_PROMPT,
#     format_diffs_for_analysis,
#     TEST_GENERATION_STRUCTURED_PROMPT
# )

from llm_agent_prompts_v2 import (
    create_analysis_prompt, 
    REVIEW_COMMENT_GENERATION_PROMPT,
    format_diffs_for_analysis,
    TEST_GENERATION_STRUCTURED_PROMPT
)
   
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

# ============================================================================
# STATE SCHEMA
# ============================================================================

class LLMReviewAgentState(TypedDict):
    # Input (from Git Agent)
    owner: str
    repo: str
    pull_number: int
    diffs: List[Dict[str, Any]]  # Code diffs to review
    
    # Output (for Jira Agent and Git Agent Write)
    review_comments: Optional[str]  # Formatted comments for PR
    bugs_found: Optional[List[Dict[str, Any]]]  # Bug details for Jira
    test_suggestions: Optional[str]  # Unit test code
    
    # Internal state
    llm_analysis: Optional[Dict[str, Any]]
    hallucination_check: Optional[Dict[str, Any]]
    validated_bugs: Optional[List[Dict[str, Any]]]


# ============================================================================
# NODE FUNCTIONS
# ============================================================================

def validate_bug_against_code(bug: Dict[str, Any], diffs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Validate a single bug finding against actual code diffs
    """
    validation = {
        "bug_type": bug.get("type", "unknown"),
        "is_valid": True,
        "issues": []
    }
    
    location = bug.get("location", "")
    
    if location:
        filename = location.split(":")[0] if ":" in location else location
        file_exists = any(d["filename"] == filename for d in diffs)
        
        if not file_exists:
            validation["is_valid"] = False
            validation["issues"].append(f"File '{filename}' not in PR changes")
    
    if ":" in location:
        try:
            line_num = int(location.split(":")[1])
            if line_num < 1 or line_num > 10000:
                validation["is_valid"] = False
                validation["issues"].append(f"Invalid line number: {line_num}")
        except (ValueError, IndexError):
            validation["issues"].append("Invalid location format")
    
    description = bug.get("description", "")
    if len(description) < 10:
        validation["is_valid"] = False
        validation["issues"].append("Description too vague")
    
    vague_patterns = [
        "might have", "could potentially", "may cause",
        "possible issue", "needs review", "consider"
    ]
    if any(pattern in description.lower() for pattern in vague_patterns):
        validation["issues"].append("Potentially vague finding")
    
    return validation

async def init_llm_agent_state_node(state: LLMReviewAgentState) -> LLMReviewAgentState:
    """Initialize LLM Review Agent state"""
    print("\n[LLM AGENT] Initializing state...")
    
    state["review_comments"] = None
    state["bugs_found"] = []
    state["test_suggestions"] = None
    state["llm_analysis"] = None
    state["hallucination_check"] = None
    state["validated_bugs"] = []
    
    print(f"✅ LLM Agent initialized - {len(state['diffs'])} diffs to review")
    
    return state


async def analyze_code_with_llm_node(state: LLMReviewAgentState) -> LLMReviewAgentState:
    """Analyze code diffs with LLM"""
    print("\n[NODE 1] Analyzing code with LLM...")
    
    try:
        async def llm_operation():
            genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
            model = genai.GenerativeModel('gemini-2.0-flash-exp')
            
            full_prompt = create_analysis_prompt(state["diffs"])
            response = model.generate_content(full_prompt)
            return response.text.strip()
        
        response_text = await retry_with_backoff(llm_operation, max_retries=3)
        
        print(f"\n[DEBUG] LLM Raw Response:\n{response_text[:500]}...\n")
        
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        
        if json_match:
            try:
                analysis = json.loads(json_match.group(0))
                state["llm_analysis"] = analysis
                
                # ===== DEBUG: Print llm_analysis structure =====
                print("\n" + "-"*60)
                print("DEBUG: LLM_ANALYSIS STRUCTURE")
                print("-"*60)
                print(json.dumps(analysis, indent=2, default=str))
                print("-"*60 + "\n")
                # ==============================================
                
                print(f"[DEBUG] Parsed Analysis:")
                print(f"  Bugs: {len(analysis.get('bugs', []))}")
                print(f"  Quality Issues: {len(analysis.get('code_quality_issues', []))}")
                print(f"  Security Issues: {len(analysis.get('security_issues', []))}")
                print(f"  Summary: {analysis.get('summary', 'N/A')[:100]}...")
                
                print(f"\n✅ Analysis complete - {len(analysis.get('bugs', []))} bugs found")
            except json.JSONDecodeError:
                print("⚠️  Failed to parse LLM response as JSON")
                state["llm_analysis"] = {"bugs": [], "summary": response_text}
        else:
            print("⚠️  No JSON found in LLM response")
            state["llm_analysis"] = {"bugs": [], "summary": response_text}
    
    except Exception as e:
        print(f"❌ LLM analysis failed after retries: {str(e)}")
        print("⚠️  Falling back to empty analysis")
        state["llm_analysis"] = {
            "bugs": [],
            "error": str(e),
            "summary": "Analysis failed - no bugs detected"
        }
    
    return state

async def validate_llm_findings_node(state: LLMReviewAgentState) -> LLMReviewAgentState:
    """
    Validate LLM findings against actual code (HALLUCINATION DETECTION)
    """
    print("\n[NODE 1.5] Validating LLM findings against actual code...")
    
    analysis = state.get("llm_analysis", {})
    bugs = analysis.get("bugs", [])
    
    validation_results = {
        "total_bugs": len(bugs),
        "validated_bugs": 0,
        "hallucinated_bugs": 0,
        "validation_details": []
    }
    
    validated_bugs = []
    
    for bug in bugs:
        bug_validation = validate_bug_against_code(bug, state["diffs"])
        
        if bug_validation["is_valid"]:
            validated_bugs.append(bug)
            validation_results["validated_bugs"] += 1
        else:
            validation_results["hallucinated_bugs"] += 1
        
        validation_results["validation_details"].append(bug_validation)
    
    state["hallucination_check"] = validation_results
    state["validated_bugs"] = validated_bugs
    
    if state["llm_analysis"]:
        state["llm_analysis"]["bugs"] = validated_bugs
    
    # ===== DEBUG: Print hallucination_check structure =====
    print("\n" + "-"*60)
    print("DEBUG: HALLUCINATION_CHECK STRUCTURE")
    print("-"*60)
    print(json.dumps(validation_results, indent=2, default=str))
    print("-"*60 + "\n")
    # ====================================================
    
    print(f"✅ Validation complete:")
    print(f"   Valid: {validation_results['validated_bugs']}/{validation_results['total_bugs']}")
    print(f"   Hallucinated: {validation_results['hallucinated_bugs']}/{validation_results['total_bugs']}")
    
    if validation_results['hallucinated_bugs'] > 0:
        print(f"⚠️  Filtered out {validation_results['hallucinated_bugs']} potentially hallucinated findings")
    
    return state

async def generate_review_comments_node(state: LLMReviewAgentState) -> LLMReviewAgentState:
    """Generate structured PR review comments"""
    print("\n[NODE 2] Generating review comments...")
    
    analysis = state.get("llm_analysis", {})
    if not analysis or analysis.get("error"):
        print("⚠️  Skipping review generation (no valid analysis)")
        state["review_comments"] = None
        return state
    
    try:
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        model = genai.GenerativeModel('gemini-2.0-flash-exp')
        
        prompt = REVIEW_COMMENT_GENERATION_PROMPT.format(
            analysis=json.dumps(analysis, indent=2)
        )
        
        response = model.generate_content(prompt)
        response_text = response.text.strip()
        
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if json_match:
            try:
                review_structure = json.loads(json_match.group(0))
                state["review_comments"] = review_structure
                
                # ===== DEBUG: Print review_comments structure =====
                print("\n" + "-"*60)
                print("DEBUG: REVIEW_COMMENTS STRUCTURE")
                print("-"*60)
                print(json.dumps(review_structure, indent=2, default=str))
                print("-"*60 + "\n")
                # =================================================
                
                print(f"✅ Structured review generated")
            except json.JSONDecodeError:
                print("⚠️  Failed to parse review comments")
                state["review_comments"] = None
        else:
            state["review_comments"] = None
    
    except Exception as e:
        print(f"❌ Failed to generate review comments: {str(e)}")
        state["review_comments"] = None
    
    return state


async def identify_bugs_node(state: LLMReviewAgentState) -> LLMReviewAgentState:
    """Identify bugs from analysis"""
    print("\n[NODE 3] Identifying bugs...")
    
    analysis = state.get("llm_analysis", {})
    bugs = analysis.get("bugs", [])
    
    # Store bugs with additional context
    state["bugs_found"] = []
    for bug in bugs:
        state["bugs_found"].append({
            "severity": bug.get("severity", "medium"),
            "type": bug.get("type", "unknown"),
            "description": bug.get("description", ""),
            "location": bug.get("location", ""),
            "suggestion": bug.get("suggestion", ""),
            "pr_number": state["pull_number"],
            "repo": f"{state['owner']}/{state['repo']}"
        })
    
    # ===== DEBUG: Print bugs_found structure =====
    print("\n" + "-"*60)
    print("DEBUG: BUGS_FOUND STRUCTURE")
    print("-"*60)
    print(json.dumps(state["bugs_found"], indent=2, default=str))
    print("-"*60 + "\n")
    # ============================================
    
    print(f"✅ Found {len(state['bugs_found'])} bugs")
    if state["bugs_found"]:
        for i, bug in enumerate(state["bugs_found"], 1):
            print(f"   [{i}] {bug['severity'].upper()}: {bug['type']} - {bug['description'][:60]}...")
    
    return state

async def suggest_tests_node(state: LLMReviewAgentState) -> LLMReviewAgentState:
    """Generate structured unit test suggestions"""
    print("\n[NODE 4] Suggesting unit tests...")
    
    analysis = state.get("llm_analysis", {})
    bugs = analysis.get("bugs", [])
    
    if not bugs or analysis.get("error"):
        print("⚠️  No bugs to generate tests for")
        state["test_suggestions"] = None
        return state
    
    try:
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        model = genai.GenerativeModel('gemini-2.0-flash-exp')
        
        diffs_text = format_diffs_for_analysis(state["diffs"])
        bugs_text = json.dumps(bugs, indent=2)
        
        prompt = TEST_GENERATION_STRUCTURED_PROMPT.format(
            diffs=diffs_text,
            bugs=bugs_text
        )
        
        response = model.generate_content(prompt)
        response_text = response.text.strip()
        
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if json_match:
            try:
                test_structure = json.loads(json_match.group(0))
                state["test_suggestions"] = test_structure
                
                # ===== DEBUG: Print test_suggestions structure =====
                print("\n" + "-"*60)
                print("DEBUG: TEST_SUGGESTIONS STRUCTURE")
                print("-"*60)
                print(json.dumps(test_structure, indent=2, default=str))
                print("-"*60 + "\n")
                # ==================================================
                
                print(f"✅ {len(test_structure.get('test_cases', []))} test cases generated")
            except json.JSONDecodeError:
                print("⚠️  Failed to parse test suggestions")
                state["test_suggestions"] = None
        else:
            state["test_suggestions"] = None
    
    except Exception as e:
        print(f"❌ Failed to generate test suggestions: {str(e)}")
        state["test_suggestions"] = None
    
    return state

# ============================================================================
# GRAPH CONSTRUCTION
# ============================================================================

def create_llm_review_agent_graph():
    """Build LLM Review Agent graph"""
    print("\n🔧 Building LLM Review Agent Graph...")
    
    workflow = StateGraph(LLMReviewAgentState)
    
    workflow.add_node("INIT", init_llm_agent_state_node)
    workflow.add_node("ANALYZE_CODE", analyze_code_with_llm_node)
    workflow.add_node("VALIDATE_FINDINGS", validate_llm_findings_node)
    workflow.add_node("GENERATE_REVIEW", generate_review_comments_node)
    workflow.add_node("IDENTIFY_BUGS", identify_bugs_node)
    workflow.add_node("SUGGEST_TESTS", suggest_tests_node)
    
    workflow.add_edge(START, "INIT")
    workflow.add_edge("INIT", "ANALYZE_CODE")
    workflow.add_edge("ANALYZE_CODE", "VALIDATE_FINDINGS")
    workflow.add_edge("VALIDATE_FINDINGS", "GENERATE_REVIEW")
    workflow.add_edge("GENERATE_REVIEW", "IDENTIFY_BUGS")
    workflow.add_edge("IDENTIFY_BUGS", "SUGGEST_TESTS")
    workflow.add_edge("SUGGEST_TESTS", END)
    
    app = workflow.compile()
    
    save_graph_as_png(app, "llm_review_agent")
    print("✅ LLM Review Agent compiled\n")
    
    return app


# Export graph
llm_review_agent_graph = create_llm_review_agent_graph()


# ============================================================================
# MAIN - For Testing
# ============================================================================

def main():
    """Test LLM Review Agent standalone"""
    
    async def test():
        test_state = LLMReviewAgentState(
            owner="promptlyaig",
            repo="issue-tracker",
            pull_number=1,
            diffs=[
                {
                    "filename": "test.py",
                    "language": "py",
                    "additions": 10,
                    "deletions": 2,
                    "patch": "dummy patch"
                }
            ]
        )
        
        result = await llm_review_agent_graph.ainvoke(test_state)
        
        print("\n" + "="*70)
        print("LLM AGENT TEST - COMPLETE OUTPUT")
        print("="*70)
        print(f"\n1. Review Comments Type: {type(result.get('review_comments'))}")
        print(f"   Keys: {result.get('review_comments', {}).keys() if isinstance(result.get('review_comments'), dict) else 'Not a dict'}")
        
        print(f"\n2. Bugs Found: {len(result.get('bugs_found', []))}")
        if result.get('bugs_found'):
            print(f"   First bug keys: {result['bugs_found'][0].keys()}")
        
        print(f"\n3. Test Suggestions Type: {type(result.get('test_suggestions'))}")
        print(f"   Keys: {result.get('test_suggestions', {}).keys() if isinstance(result.get('test_suggestions'), dict) else 'Not a dict'}")
        if isinstance(result.get('test_suggestions'), dict):
            print(f"   Test cases: {len(result.get('test_suggestions', {}).get('test_cases', []))}")
        
        print("="*70)
    
    asyncio.run(test())

if __name__ == "__main__":
    main()