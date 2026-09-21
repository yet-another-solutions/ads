"""Allowlisted operational reasons, never arbitrary exception/provider text."""

SAFE_REASONS = frozenset(
    {
        "invalid_summary_envelope",
        "invalid_summary_json",
        "empty_summary",
        "memory_must_be_first",
        "invalid_tool_lifecycle",
        "orphan_tool_result",
        "unknown_task_lifecycle",
        "invalid_task_lifecycle",
        "incomplete_tool_lifecycle",
        "summary_output_limit",
        "invalid_memory_position",
        "insufficient_compaction_progress",
        "no_safe_fitting_prefix",
        "no_compaction_result",
        "provider_context_overflow",
        "model_invocation_failed",
        "invalid_model_response",
        "meter_failed",
        "invalid_meter_result",
        "frame_source_overflow",
        "unstable_meter_result",
        "unauthorized_memory",
        "unknown_recall_tool",
        "recall_prohibition_does_not_fit",
        "invalid_recall_call_id",
        "recall_batch_closure_does_not_fit",
        "invalid_recall_tool_calls",
        "recall_tools_prohibited",
        "empty_frame_answer",
        "context_service_failed",
        "internal_error",
        "context starvation. recall prohibited",
    }
)


def failure_reason(exc: Exception) -> str:
    # Only our typed exceptions may supply a reason; even their text is allowlisted.
    from ads_context_runtime.frames import ContextFailure

    reason = str(exc) if isinstance(exc, ContextFailure) else ""
    return reason if reason in SAFE_REASONS else "internal_error"
