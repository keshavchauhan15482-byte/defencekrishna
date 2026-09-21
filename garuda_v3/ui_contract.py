"""Fail-closed V94 UI claim transformations for the integrated runtime.

The research UI source is intentionally kept reusable by the base/offline server.  The
integrated runtime applies these exact transforms while serving JavaScript so unsupported
telemetry cannot be presented as a validated stage or autonomous-ready decision.
"""
from __future__ import annotations


_APP_STAGE_OLD = "text('stage',f.predicted_attack_stage||f.stage_hint?.title||'Insufficient stage evidence');text('stageText',f.predicted_attack_stage?f.stage_status:'Heuristic-based, not ML-trained. '+(f.stage_hint?.rule||'')+' '+(f.stage_hint?.caveat||''));"
_APP_STAGE_NEW = "const runtimeSupport=f.runtime_support||{};const supportValidated=runtimeSupport.supported===true;if(supportValidated&&f.predicted_attack_stage){text('stage',String(f.predicted_attack_stage));text('stageText',String(f.stage_status||'Supported stage-model output'));}else{text('stage','UNRESOLVED / INSUFFICIENT EVIDENCE');text('stageText',String(f.operating_mode||'SHADOW_UNRESOLVED')+' · '+String(f.stage_status||runtimeSupport.reason||'Runtime support proof unavailable or out of support')+' · advisory only');}"

_REFERENCE_POSTURE_OLD = "text('kpiPosture',s.enforcement_enabled?'Enforcement enabled':'Review only');"
_REFERENCE_POSTURE_NEW = "const supportGate=s.runtime_support_gate||{};text('kpiPosture',supportGate.present?(s.enforcement_enabled?'SUPPORT-GATED ENFORCE':'SUPPORT-GATED REVIEW'):'SHADOW / ADVISORY');"

_REFERENCE_STATUS_OLD = "text('statusText',f.alert?'ALERT':'NORMAL');text('riskBadge',peak>=.75?'HIGH':peak>=.5?'ELEVATED':'LOW');\n  text('suspiciousCount',f.alert?'1':'0');"
_REFERENCE_STATUS_NEW = "const supportValidated=f.runtime_support?.supported===true;text('statusText',supportValidated?(f.alert?'ALERT':'NORMAL'):'ADVISORY');text('riskBadge',supportValidated?(peak>=.75?'HIGH':peak>=.5?'ELEVATED':'LOW'):'UNRESOLVED');\n  text('suspiciousCount',supportValidated?(f.alert?'1':'0'):'—');"


def _replace_required(source: str, old: str, new: str, label: str) -> str:
    if old not in source:
        raise RuntimeError(f'V94 UI contract marker missing: {label}')
    return source.replace(old, new, 1)


def harden_ui_asset(name: str, source: str) -> str:
    """Return the integrated-runtime version of a JavaScript asset.

    Exact required markers make drift fail closed: if the underlying UI changes without
    updating this contract, the integrated runtime refuses to serve a potentially stale
    claim surface rather than silently restoring heuristic/unsupported wording.
    """
    if name == 'app.js':
        hardened = _replace_required(source, _APP_STAGE_OLD, _APP_STAGE_NEW, 'secondary_stage_abstention')
        if 'Heuristic-based, not ML-trained.' in hardened:
            raise RuntimeError('V94 UI hardening left a heuristic stage fallback behind')
        return hardened
    if name == 'reference-live.js':
        hardened = _replace_required(source, _REFERENCE_POSTURE_OLD, _REFERENCE_POSTURE_NEW, 'homepage_runtime_posture')
        hardened = _replace_required(hardened, _REFERENCE_STATUS_OLD, _REFERENCE_STATUS_NEW, 'homepage_support_status')
        return hardened
    return source
