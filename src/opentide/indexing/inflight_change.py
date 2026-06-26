"""Collect pull-request / merge-request metadata for inflight preview shards."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

INFLIGHT_SHARD_SCHEMA = "inflight.shard::1.0"


def _normalise_source_path(path: Path | str) -> str:
    root = Path(os.getenv("OPENTIDE_REPO_ROOT", ".")).resolve()
    try:
        return Path(path).resolve().relative_to(root).as_posix()
    except ValueError:
        return Path(path).as_posix()


def _github_metadata(source_path: str) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    event_path = os.getenv("GITHUB_EVENT_PATH")
    if event_path and Path(event_path).is_file():
        try:
            payload = json.loads(Path(event_path).read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload = {}
    pr = payload.get("pull_request") if isinstance(payload.get("pull_request"), dict) else {}
    head = pr.get("head") if isinstance(pr.get("head"), dict) else {}
    base = pr.get("base") if isinstance(pr.get("base"), dict) else {}
    return {
        "platform": "github",
        "number": pr.get("number"),
        "url": pr.get("html_url"),
        "title": pr.get("title"),
        "head_ref": os.getenv("GITHUB_HEAD_REF") or head.get("ref"),
        "base_ref": os.getenv("GITHUB_BASE_REF") or base.get("ref"),
        "head_sha": os.getenv("GITHUB_SHA") or head.get("sha"),
        "source_path": source_path,
    }


def _gitlab_metadata(source_path: str) -> dict[str, Any]:
    iid = os.getenv("CI_MERGE_REQUEST_IID")
    project_url = os.getenv("CI_PROJECT_URL", "")
    url = f"{project_url}/-/merge_requests/{iid}" if iid and project_url else None
    return {
        "platform": "gitlab",
        "number": int(iid) if iid and iid.isdigit() else iid,
        "url": url,
        "title": os.getenv("CI_MERGE_REQUEST_TITLE"),
        "head_ref": os.getenv("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"),
        "base_ref": os.getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME"),
        "head_sha": os.getenv("CI_COMMIT_SHA"),
        "source_path": source_path,
    }


def _azure_metadata(source_path: str) -> dict[str, Any]:
    number = os.getenv("SYSTEM_PULLREQUEST_PULLREQUESTNUMBER") or os.getenv(
        "SYSTEM_PULLREQUEST_PULLREQUESTID"
    )
    return {
        "platform": "azure",
        "number": int(number) if number and str(number).isdigit() else number,
        "url": os.getenv("SYSTEM_PULLREQUEST_PULLREQUESTURI"),
        "title": os.getenv("SYSTEM_PULLREQUEST_PULLREQUESTTITLE"),
        "head_ref": (os.getenv("SYSTEM_PULLREQUEST_SOURCEBRANCH") or "").replace("refs/heads/", ""),
        "base_ref": (os.getenv("SYSTEM_PULLREQUEST_TARGETBRANCH") or "").replace("refs/heads/", ""),
        "head_sha": os.getenv("BUILD_SOURCEVERSION"),
        "source_path": source_path,
    }


def _local_metadata(source_path: str) -> dict[str, Any]:
    return {
        "platform": "local",
        "number": None,
        "url": None,
        "title": None,
        "head_ref": None,
        "base_ref": None,
        "head_sha": None,
        "source_path": source_path,
    }


def collect_change_metadata(yaml_path: Path | str) -> dict[str, Any]:
    """Return normalised PR/MR metadata for the active CI platform."""
    from opentide.deployment.ci import CIEnvironment

    override = os.getenv("INFLIGHT_CHANGE_JSON", "").strip()
    if override:
        try:
            data = json.loads(override)
            if isinstance(data, dict):
                data.setdefault("source_path", _normalise_source_path(yaml_path))
                return data
        except json.JSONDecodeError:
            pass

    source_path = _normalise_source_path(yaml_path)
    env = CIEnvironment().environment
    match env:
        case CIEnvironment.CIPlatforms.GitHubActions:
            meta = _github_metadata(source_path)
        case CIEnvironment.CIPlatforms.GitlabCI:
            meta = _gitlab_metadata(source_path)
        case CIEnvironment.CIPlatforms.AzurePipeline:
            meta = _azure_metadata(source_path)
        case _:
            meta = _local_metadata(source_path)
    meta["recorded_at"] = datetime.now(timezone.utc).isoformat()
    return meta


def build_shard_payload(object_body: dict[str, Any], yaml_path: Path | str) -> dict[str, Any]:
    """Wrap a parsed object document with inflight shard envelope and change metadata."""
    return {
        "schema": INFLIGHT_SHARD_SCHEMA,
        "written_at": datetime.now(timezone.utc).isoformat(),
        "object": object_body,
        "change": collect_change_metadata(yaml_path),
    }
