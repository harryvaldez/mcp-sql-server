from __future__ import annotations

import hashlib
import pathlib
import re
import time
from typing import Any

from fastapi import APIRouter, HTTPException
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.responses import Response

from src.diagnostics.usage_summary import summarize_audit_events
from src.tools.dashboard_payloads import build_sessions_dashboard_full
from src.tools.dashboard_page_store import get_dashboard_page
from src.tools.input_validation import validate_database_name, validate_positive_int
from src.tools.query_catalog import (
    active_sessions_query,
    blocking_chain_query,
    lock_chain_query,
    tran_locks_query,
    waiting_tasks_query,
)

REQUEST_COUNT = Counter(
    "mcp_requests_total", "Total MCP tool calls", ["tool", "instance", "decision"]
)
REQUEST_LATENCY = Histogram(
    "mcp_query_latency_ms", "MCP query latency in ms", ["tool", "instance"]
)


def build_diagnostics_router(state: Any) -> APIRouter:
    router = APIRouter()
    start_time = time.time()

    @router.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": state.version,
            "uptime_seconds": int(time.time() - start_time),
            "instances": state.connection_manager.healthcheck_all(),
        }

    @router.get("/readiness")
    def readiness() -> dict[str, Any]:
        health = state.connection_manager.healthcheck_all()
        required_ok = all(v.get("state") == "healthy" for v in health.values())
        return {
            "ready": required_ok,
            "components": {
                "config_loaded": True,
                "policy_active": True,
                "rate_limiter_active": True,
                "session_manager_active": True,
            },
            "instances": health,
        }

    @router.get("/security")
    def security() -> dict[str, Any]:
        policy_path = pathlib.Path(state.policy_path)
        raw = policy_path.read_bytes() if policy_path.exists() else b""
        registered_tools = list(getattr(state, "registered_tools", []))
        advanced_tools = [
            name
            for name in registered_tools
            if "_analyze_" in name or name.endswith("_dashboard")
        ]
        auth_cfg = getattr(state, "auth", None)
        auth_summary = {
            "auth_mode": getattr(auth_cfg, "auth_mode", "disabled"),
            "azure_auth_enabled": bool(getattr(auth_cfg, "azure_auth_enabled", False)),
            "azure_group_authorization_enabled": bool(
                getattr(auth_cfg, "azure_group_authorization_enabled", False)
            ),
            "required_scopes": list(
                getattr(auth_cfg, "azure_required_scopes", []) or []
            ),
            "read_group_count": len(getattr(auth_cfg, "azure_read_groups", []) or []),
            "write_group_count": len(getattr(auth_cfg, "azure_write_groups", []) or []),
        }
        return {
            "write_mode_default": state.policy.write_mode_default,
            "rate_limit_backend": state.rate_limit_backend,
            "tool_flag_env_applied": getattr(state, "tool_flag_env_applied", False),
            "policy_checksum_sha256": hashlib.sha256(raw).hexdigest(),
            "denied_requests": state.denied_requests,
            "registered_tools_count": len(registered_tools),
            "registered_tools": registered_tools,
            "advanced_tools_count": len(advanced_tools),
            "advanced_tools": advanced_tools,
            "last_secret_refresh_utc": state.last_secret_refresh_utc,
            "auth": auth_summary,
        }

    @router.get("/pool")
    def pool() -> dict[str, Any]:
        return {"instances": state.connection_manager.get_pool_diagnostics()}

    @router.get("/metrics")
    def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @router.get("/audit-summary")
    def audit_summary() -> dict[str, Any]:
        audit_path = pathlib.Path(state.audit_path)
        summary = summarize_audit_events(audit_path)
        return {"events": summary["events"], "latest": summary["latest"]}

    @router.get("/tool-usage-summary")
    def tool_usage_summary() -> dict[str, Any]:
        audit_path = pathlib.Path(state.audit_path)
        return summarize_audit_events(audit_path)

    @router.get("/sessions-dashboard/runtime")
    def sessions_dashboard_runtime(
        instance_number: int = 1,
        database_name: str = "master",
        lookback_minutes: int = 15,
        include_locks: bool = True,
        actor: str = "system",
    ) -> dict[str, Any]:
        db_name = validate_database_name(database_name)
        validate_positive_int(lookback_minutes, "lookback_minutes", 1, 1440)

        instance_ids = state.connection_manager.list_enabled_instances()
        number_by_instance = {
            idx: instance_id for idx, instance_id in enumerate(instance_ids, start=1)
        }
        if instance_number not in number_by_instance:
            raise HTTPException(
                status_code=400,
                detail=f"INVALID_INPUT: instance_number must be one of {sorted(number_by_instance)}",
            )
        instance_id = number_by_instance[instance_number]

        state.session_manager.touch(actor, "runtime-dashboard")
        state.rate_limiter.allow(actor)
        state.write_guard.enforce("sessions_dashboard_runtime", "SELECT 1")

        sessions = state.connection_manager.execute_catalog_query(
            instance_id,
            db_name,
            active_sessions_query(200),
            200,
        )
        lock_rows = {"rows": []}
        tran_lock_rows = {"rows": []}
        waiting_rows = {"rows": []}
        blocking_chain_rows = {"rows": []}
        if include_locks:
            lock_rows = state.connection_manager.execute_catalog_query(
                instance_id,
                db_name,
                lock_chain_query(200),
                200,
            )
            tran_lock_rows = state.connection_manager.execute_catalog_query(
                instance_id,
                db_name,
                tran_locks_query(200),
                200,
            )
            waiting_rows = state.connection_manager.execute_catalog_query(
                instance_id,
                db_name,
                waiting_tasks_query(200),
                200,
            )
            blocking_chain_rows = state.connection_manager.execute_catalog_query(
                instance_id,
                db_name,
                blocking_chain_query(200),
                200,
            )

        head_blockers: list[int] = []
        for row in lock_rows["rows"]:
            blocker = row.get("blocking_session_id")
            if blocker is None:
                continue
            try:
                blocker_id = int(blocker)
            except (TypeError, ValueError):
                continue
            if blocker_id > 0 and blocker_id not in head_blockers:
                head_blockers.append(blocker_id)

        return build_sessions_dashboard_full(
            instance_number=instance_number,
            database_name=db_name,
            sessions=sessions["rows"],
            lock_chains=lock_rows["rows"],
            tran_locks=tran_lock_rows["rows"],
            waiting_tasks=waiting_rows["rows"],
            head_blockers=head_blockers,
            blocking_chains=blocking_chain_rows["rows"],
            lookback_minutes=lookback_minutes,
            include_locks=include_locks,
            actor=actor,
        )

    @router.get("/dashboards/{request_id}")
    def dashboard_page(request_id: str) -> Response:
        # Validate request_id: alphanumerics, hyphen, underscore only (no path traversal)
        if not request_id or not re.match(r"^[a-zA-Z0-9_-]{1,255}$", request_id):
            raise HTTPException(status_code=400, detail="Invalid request_id format")
        html = get_dashboard_page(request_id)
        if html is None:
            raise HTTPException(
                status_code=404, detail="dashboard_page_not_found_or_expired"
            )
        return Response(content=html, media_type="text/html")

    return router
