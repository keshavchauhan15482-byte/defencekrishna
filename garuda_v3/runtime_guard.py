"""Fail-closed local runtime boundary; not an enterprise certification."""
import ipaddress
import os


def deployment_profile():
    profile = os.environ.get('GARUDA_DEPLOYMENT_PROFILE', 'local')
    if profile not in ('local', 'pilot'):
        raise ValueError('GARUDA_DEPLOYMENT_PROFILE must be local or pilot')
    return profile


def validate_startup(reader, operator, key, scopes, enforce, lab_automation):
    profile = deployment_profile()
    if enforce and (len(key) < 32 or key in (reader, operator) or not scopes):
        raise ValueError('Enforcement requires an independent 32+ character signing key and explicit CIDR scope')
    if profile == 'pilot' and (enforce or lab_automation):
        raise ValueError('Pilot profile is shadow-only; enforcement and lab automation must be disabled')
    return profile


def validate_bind(host):
    # Do not resolve caller-controlled hostnames or accept wildcard/public binds.
    if host == 'localhost':
        return
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError('Runtime listener requires an explicit loopback address') from exc
    if not address.is_loopback:
        raise ValueError('Runtime listener must remain loopback-only; use an authenticated TLS gateway')


def framing_error(headers, method, max_body):
    if len(headers.get_all('Host', [])) != 1:
        return 400, 'Exactly one Host header required'
    if headers.get_all('Transfer-Encoding', []):
        return 400, 'Transfer-Encoding is not supported'
    lengths = headers.get_all('Content-Length', [])
    if len(lengths) > 1:
        return 400, 'Duplicate Content-Length rejected'
    if method == 'POST' and not lengths:
        return 411, 'Content-Length required'
    if lengths:
        raw = lengths[0]
        if not raw or not raw.isascii() or not raw.isdecimal():
            return 400, 'Invalid Content-Length'
        length = int(raw) if len(raw) <= 10 else max_body + 1
        if length > max_body:
            return 413, 'Request body exceeds runtime limit'
        if method == 'POST' and length == 0:
            return 400, 'Empty POST body rejected'
        if method != 'POST' and length:
            return 400, 'Request body not supported for this method'
    return None
