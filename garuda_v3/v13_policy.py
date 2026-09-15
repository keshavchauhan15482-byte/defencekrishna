"""Fail-closed threshold export used after V12 diagnostics.

Diagnostic thresholds may be reported for analysis, but only a fully supported,
calibrated and confidence-gated threshold may be exported as actionable.
"""
from __future__ import annotations


def approved_threshold(*, selected_threshold, calibration_fitted: bool, development_support_ready: bool, confidence_gate_passed: bool):
    if not calibration_fitted or not development_support_ready or not confidence_gate_passed:
        return None
    if selected_threshold is None:
        return None
    try:
        value = float(selected_threshold)
    except (TypeError, ValueError):
        return None
    if not 0.0 <= value <= 1.0:
        return None
    return value


def risk_output_permission(**kwargs) -> bool:
    return approved_threshold(**kwargs) is not None
