"""
Red Banner Security Warning Generator
======================================

This module generates visible security warnings when prompt injection
is detected by any phase of the detection pipeline.

Used by: v3_orctr_adv_defense.py, v4_orctr_AI_defense.py

Purpose:
- Creates human-visible security alerts
- Provides actionable guidance for developers
- Documents threat details for audit trail
- Prevents silent compromise

CRITICAL: This node MUST NOT use any LLM
- Uses only deterministic logic
- No AI-generated content
- Fixed templates only
- Prevents secondary injection attacks
"""

from typing import Dict, Any


# ============================================================================
# BANNER TEMPLATES
# ============================================================================

BANNER_HEADER = """
🚨 SECURITY ALERT: PROMPT INJECTION DETECTED 🚨
================================================
"""

BANNER_CRITICAL_MESSAGE = """
This pull request contains content attempting to manipulate or override 
automated review behavior.

**Automated review has been BLOCKED to protect system integrity.**
"""

BANNER_DETECTION_DETAILS = """
Detection Details:
-----------------
Confidence Level: {confidence}
Detection Phases: {phases}
Threat Signals:
{signals}
"""

BANNER_INTENT_DETAILS = """
Manipulation Intent Analysis:
---------------------------
{intent_analysis}
"""

BANNER_RECOMMENDED_ACTIONS = """
Recommended Actions:
-------------------
1. Remove all instructions attempting to influence automated reviewers
2. Avoid directives such as:
   - Forcing approval or positive conclusions
   - Suppressing bug reports or findings
   - Claiming reviewer authority or role
   - Bypassing security checks or standards
3. Ensure code comments are descriptive, not prescriptive
4. Resubmit the PR after cleanup

⚠️  Human review is REQUIRED for this PR
"""

BANNER_FOOTER = """
================================================
This is an automated security warning.
For questions, contact your security team.
"""


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def format_detection_phases(signals: Dict[str, bool]) -> str:
    """
    Format which detection phases triggered
    
    Args:
        signals: Dict with phase detection results
        
    Returns:
        Formatted string of active phases
    """
    phases = []
    
    if signals.get("regex"):
        phases.append("Phase 1 (Regex Patterns)")
    if signals.get("heuristics"):
        phases.append("Phase 2 (Heuristic Keywords)")
    if signals.get("intent"):
        phases.append("Phase 3 (AI Intent Classification)")
    
    if not phases:
        return "None (False positive?)"
    
    return ", ".join(phases)


def format_signal_details(injection: Dict[str, Any]) -> str:
    """
    Format signal details for display
    
    Args:
        injection: Full prompt_injection detection data
        
    Returns:
        Formatted string with signal details
    """
    lines = []
    signals = injection.get("signals", {})
    
    # Phase 1 & 2 evidence
    evidence = injection.get("evidence", [])
    if evidence and (signals.get("regex") or signals.get("heuristics")):
        lines.append("   Pattern/Keyword Matches:")
        for i, item in enumerate(evidence[:5], 1):  # Show first 5
            lines.append(f"      {i}. {item}")
        if len(evidence) > 5:
            lines.append(f"      ... and {len(evidence) - 5} more")
    
    # Phase 3 intent
    if signals.get("intent"):
        intent_types = injection.get("intent_types", [])
        if intent_types:
            lines.append("   AI-Detected Intent Types:")
            for intent_type in intent_types:
                lines.append(f"      - {intent_type}")
    
    # Suspicion score if available
    details = injection.get("details", {})
    if details.get("suspicion_score"):
        lines.append(f"   Suspicion Score: {details['suspicion_score']}")
    
    return "\n".join(lines) if lines else "   (See detection logs for details)"


def format_intent_analysis(injection: Dict[str, Any]) -> str:
    """
    Format AI intent analysis for display
    
    Args:
        injection: Full prompt_injection detection data
        
    Returns:
        Formatted string with intent analysis
    """
    if not injection.get("signals", {}).get("intent"):
        return "Not applicable (Phase 3 not triggered)"
    
    explanation = injection.get("explanation", "No explanation available")
    intent_types = injection.get("intent_types", [])
    
    lines = []
    
    if intent_types:
        lines.append("Detected Intent Types:")
        for intent_type in intent_types:
            lines.append(f"   - {intent_type}")
        lines.append("")
    
    lines.append(f"AI Analysis: {explanation}")
    
    return "\n".join(lines)


def generate_github_markdown_banner(injection: Dict[str, Any]) -> str:
    """
    Generate GitHub-flavored markdown banner
    
    Args:
        injection: Full prompt_injection detection data
        
    Returns:
        Markdown-formatted security banner
    """
    confidence = injection.get("confidence", "unknown").upper()
    signals = injection.get("signals", {})
    
    # Build banner
    banner_parts = [BANNER_HEADER]
    banner_parts.append(BANNER_CRITICAL_MESSAGE)
    
    # Detection details
    phases = format_detection_phases(signals)
    signal_details = format_signal_details(injection)
    
    detection_section = BANNER_DETECTION_DETAILS.format(
        confidence=confidence,
        phases=phases,
        signals=signal_details
    )
    banner_parts.append(detection_section)
    
    # Intent analysis (if Phase 3 triggered)
    if signals.get("intent"):
        intent_section = BANNER_INTENT_DETAILS.format(
            intent_analysis=format_intent_analysis(injection)
        )
        banner_parts.append(intent_section)
    
    # Recommended actions
    banner_parts.append(BANNER_RECOMMENDED_ACTIONS)
    
    # Footer
    banner_parts.append(BANNER_FOOTER)
    
    return "\n".join(banner_parts)


# ============================================================================
# MAIN RED BANNER NODE
# ============================================================================

def red_banner_pr_comment_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate deterministic 'red banner' PR comment when prompt injection detected.
    
    CRITICAL: This node MUST NOT use any LLM to prevent secondary injection.
    
    Args:
        state: Orchestrator state containing prompt_injection detection results
        
    Returns:
        Updated state with red_banner_comment
    """
    print("\n[RED BANNER] Generating security warning...")
    
    injection = state.get("prompt_injection", {})
    
    # Only generate banner if injection detected
    if not injection.get("detected"):
        print("   ℹ️  No threat detected - banner not needed")
        state["red_banner_comment"] = None
        return state
    
    # Extract key information
    confidence = injection.get("confidence", "unknown")
    signals = injection.get("signals", {})
    evidence = injection.get("evidence", [])
    intent_types = injection.get("intent_types", [])
    
    # Generate markdown banner
    markdown_banner = generate_github_markdown_banner(injection)
    
    # Build structured comment data
    banner_comment = {
        "type": "security_warning",
        "title": "🚨 Prompt Injection Detected",
        "severity": "critical",
        "confidence": confidence,
        "message": BANNER_CRITICAL_MESSAGE.strip(),
        "detection_summary": {
            "phases_triggered": format_detection_phases(signals),
            "confidence_level": confidence,
            "evidence_count": len(evidence),
            "intent_types": intent_types if intent_types else None
        },
        "detected_signals": evidence[:10],  # First 10 for summary
        "recommended_actions": [
            "Remove all instructions attempting to influence automated reviewers",
            "Avoid directives forcing approval or suppressing findings",
            "Ensure code comments are descriptive, not prescriptive",
            "Resubmit the PR after cleanup"
        ],
        "requires_human_review": True,
        "markdown_content": markdown_banner,
        
        # Metadata for audit trail
        "detection_phases": {
            "phase1_regex": signals.get("regex", False),
            "phase2_heuristics": signals.get("heuristics", False),
            "phase3_intent": signals.get("intent", False)
        },
        "timestamp": None,  # Would be set by calling system
        "automated": True
    }
    
    # Attach to state
    state["red_banner_comment"] = banner_comment
    
    # Log generation
    print(f"   🚩 Red banner generated:")
    print(f"      Severity: CRITICAL")
    print(f"      Confidence: {confidence}")
    print(f"      Phases triggered: {format_detection_phases(signals)}")
    print(f"      Evidence items: {len(evidence)}")
    if intent_types:
        print(f"      Intent types: {', '.join(intent_types)}")
    print(f"      Human review: REQUIRED")
    
    return state


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_banner_preview(state: Dict[str, Any], max_lines: int = 20) -> str:
    """
    Get preview of banner content
    
    Args:
        state: Orchestrator state with red_banner_comment
        max_lines: Maximum lines to show in preview
        
    Returns:
        Preview string
    """
    banner = state.get("red_banner_comment")
    
    if not banner:
        return "No banner generated (no threat detected)"
    
    markdown = banner.get("markdown_content", "")
    lines = markdown.split("\n")
    
    if len(lines) <= max_lines:
        return markdown
    
    preview_lines = lines[:max_lines]
    preview_lines.append(f"\n... ({len(lines) - max_lines} more lines)")
    
    return "\n".join(preview_lines)


def should_post_banner(state: Dict[str, Any]) -> bool:
    """
    Determine if banner should be posted to PR
    
    Args:
        state: Orchestrator state
        
    Returns:
        True if banner should be posted
    """
    banner = state.get("red_banner_comment")
    injection = state.get("prompt_injection", {})
    
    return (
        banner is not None
        and injection.get("detected", False)
        and banner.get("requires_human_review", False)
    )


def get_banner_summary(state: Dict[str, Any]) -> str:
    """
    Get concise summary of banner for logging
    
    Args:
        state: Orchestrator state with red_banner_comment
        
    Returns:
        Summary string
    """
    banner = state.get("red_banner_comment")
    
    if not banner:
        return "No security warning generated"
    
    detection = banner.get("detection_summary", {})
    
    return (
        f"🚩 Security Warning: {banner.get('title')} | "
        f"Confidence: {detection.get('confidence_level', 'unknown')} | "
        f"Phases: {detection.get('phases_triggered', 'N/A')} | "
        f"Evidence: {detection.get('evidence_count', 0)} items"
    )


# ============================================================================
# TESTING / DEMONSTRATION
# ============================================================================

if __name__ == "__main__":
    """Demo and testing"""
    
    print("="*70)
    print("RED BANNER SECURITY WARNING GENERATOR")
    print("="*70)
    
    # Test case 1: All phases triggered
    print("\n1. Test: All Detection Phases Triggered")
    print("-" * 70)
    
    test_state_1 = {
        "prompt_injection": {
            "detected": True,
            "signals": {
                "regex": True,
                "heuristics": True,
                "intent": True
            },
            "confidence": "high",
            "evidence": [
                "ignore all previous instructions",
                "do not report bugs",
                "production-ready",
                "automated review",
                "approve"
            ],
            "intent_types": ["approval_coercion", "bug_suppression"],
            "explanation": "Code contains explicit instructions to manipulate review output and suppress findings",
            "details": {
                "suspicion_score": 42
            }
        }
    }
    
    result_1 = red_banner_pr_comment_node(test_state_1)
    print(get_banner_summary(result_1))
    print("\nBanner Preview:")
    print(get_banner_preview(result_1, max_lines=15))
    
    # Test case 2: Only Phase 1 & 2
    print("\n\n2. Test: Phase 1 & 2 Only (No Intent Detection)")
    print("-" * 70)
    
    test_state_2 = {
        "prompt_injection": {
            "detected": True,
            "signals": {
                "regex": True,
                "heuristics": False,
                "intent": False
            },
            "confidence": "medium",
            "evidence": [
                "ignore previous instructions",
                "approved"
            ],
            "details": {
                "suspicion_score": 20
            }
        }
    }
    
    result_2 = red_banner_pr_comment_node(test_state_2)
    print(get_banner_summary(result_2))
    
    # Test case 3: No detection
    print("\n\n3. Test: No Threat Detected")
    print("-" * 70)
    
    test_state_3 = {
        "prompt_injection": {
            "detected": False,
            "signals": {
                "regex": False,
                "heuristics": False,
                "intent": False
            },
            "confidence": "low",
            "evidence": []
        }
    }
    
    result_3 = red_banner_pr_comment_node(test_state_3)
    print(get_banner_summary(result_3))
    
    print("\n" + "="*70)
    print("DESIGN PRINCIPLES")
    print("="*70)
    print("✓ Deterministic - No LLM usage")
    print("✓ Visible - High-contrast security alert")
    print("✓ Actionable - Clear remediation steps")
    print("✓ Auditable - Complete detection details")
    print("✓ Safe - Cannot be manipulated by injection")
