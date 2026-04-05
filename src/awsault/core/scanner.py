"""
Surface scan engine.

Fires parameterless read-only API calls across requested services and records
which ones succeed, fail, or get denied. Uses ThreadPoolExecutor for concurrency
and boto3 paginators where available to avoid truncated results.
"""

import json
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import botocore.exceptions

from ..services import get_all_services, get_service_names


# error codes that indicate a permissions issue, not a real failure
_DENIED_CODES = frozenset({
    "AccessDenied", "AccessDeniedException", "UnauthorizedAccess",
    "AuthorizationError", "UnauthorizedOperation", "ForbiddenException",
    "InvalidClientTokenId", "AuthorizationException",
})


def _serialize(obj):
    """Fallback serializer for datetime and bytes in API responses."""
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except UnicodeDecodeError:
            return "<binary>"
    return str(obj)


def _to_json_safe(data):
    """Round-trip through JSON to ensure the data is fully serializable."""
    return json.loads(json.dumps(data, default=_serialize))


class CallResult:
    """Stores the outcome of a single API call."""

    __slots__ = ("service", "method", "status", "data", "error", "count")

    def __init__(self, service, method, status, data=None, error=None, count=0):
        self.service = service
        self.method = method
        self.status = status      # "ok", "denied", or "error"
        self.data = data
        self.error = error
        self.count = count

    def to_dict(self):
        return {
            "service": self.service,
            "method": self.method,
            "status": self.status,
            "data": self.data if self.status == "ok" else None,
            "count": self.count if self.status == "ok" else 0,
            "error": self.error if self.status != "ok" else None,
        }


class ServiceResult:
    """Aggregated results for all API calls within one service."""

    __slots__ = ("name", "calls", "ok", "denied", "errors")

    def __init__(self, name):
        self.name = name
        self.calls = []
        self.ok = 0
        self.denied = 0
        self.errors = 0

    @property
    def total(self):
        return len(self.calls)

    def add(self, result):
        self.calls.append(result)
        if result.status == "ok":
            self.ok += 1
        elif result.status == "denied":
            self.denied += 1
        else:
            self.errors += 1

    def to_dict(self):
        return {
            "summary": {"total": self.total, "ok": self.ok, "denied": self.denied, "errors": self.errors},
            "calls": [c.to_dict() for c in self.calls],
        }


def _exec_call(session, svc_name, call_def):
    """
    Execute one API call and return a CallResult.

    Tries the paginator first if configured. If the paginator is not available
    for this method, falls back to a direct call. Catches access denied errors
    and classifies them separately from other failures.
    """
    svc_cfg = get_all_services()[svc_name]
    method = call_def["method"]
    key = call_def.get("key")
    use_paginator = call_def.get("paginate", False)
    params = call_def.get("params", {})

    try:
        client = session.client(svc_cfg["client"])
    except Exception as e:
        return CallResult(svc_name, method, "error", error=str(e))

    try:
        # attempt paginated call
        if use_paginator:
            try:
                pager = client.get_paginator(method)
                collected = []
                raw_pages = []
                for page in pager.paginate(**params):
                    raw_pages.append(page)
                    if key and key in page:
                        collected.extend(page[key])

                data = _to_json_safe(collected if key else raw_pages)
                count = len(data) if isinstance(data, list) else 1
                return CallResult(svc_name, method, "ok", data=data, count=count)
            except botocore.exceptions.OperationNotPageableError:
                pass  # not actually pageable, fall through to direct call

        # direct call
        func = getattr(client, method)
        resp = func(**params)
        resp.pop("ResponseMetadata", None)

        data = resp[key] if (key and key in resp) else resp
        data = _to_json_safe(data)
        count = len(data) if isinstance(data, list) else 1
        return CallResult(svc_name, method, "ok", data=data, count=count)

    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        status = "denied" if code in _DENIED_CODES else "error"
        return CallResult(svc_name, method, status, error=f"{code}: {msg}")

    except botocore.exceptions.EndpointConnectionError:
        return CallResult(svc_name, method, "error", error="Endpoint not available in this region")

    except Exception as e:
        return CallResult(svc_name, method, "error", error=str(e))


def scan(session, targets, workers=10, on_result=None):
    """
    Run the surface scan across all targeted services.

    Launches every API call as a separate task in a thread pool. Calls
    on_result(service, method, CallResult) after each call completes,
    which the CLI uses to update the progress bar.

    Returns a dict mapping service names to ServiceResult objects.
    """
    all_svc = get_all_services()

    if "all" in targets:
        targets = get_service_names()
    else:
        valid = set(get_service_names())
        targets = [t for t in targets if t in valid]

    results = {}
    futures = {}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for svc_name in targets:
            results[svc_name] = ServiceResult(svc_name)
            for call_def in all_svc[svc_name]["calls"]:
                future = pool.submit(_exec_call, session, svc_name, call_def)
                futures[future] = (svc_name, call_def["method"])

        for future in as_completed(futures):
            svc_name, method = futures[future]
            try:
                result = future.result()
            except Exception as e:
                result = CallResult(svc_name, method, "error", error=str(e))

            results[svc_name].add(result)
            if on_result:
                on_result(svc_name, method, result)

    return results


def count_total_calls(targets):
    """Count how many API calls will be made for the given target list."""
    all_svc = get_all_services()
    if "all" in targets:
        return sum(len(s["calls"]) for s in all_svc.values())
    return sum(len(all_svc[s]["calls"]) for s in targets if s in all_svc)
