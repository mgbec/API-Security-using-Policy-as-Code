"""
Example Lambda handler demonstrating OWASP-aligned API logic.

This file exists so Semgrep (SAST) has code to scan and so the patterns
below show the application-layer controls that infra policy cannot enforce:

  API1 BOLA  - explicit ownership check before returning an object
  API3 BOPLA - response is built from an allowlist of fields, not the raw row
  API7 SSRF  - no user-controlled URL is fetched; see note below
"""

import json


def _authorized(subject: str, item: dict) -> bool:
    """OWASP API1: verify the caller owns the object before returning it."""
    return item.get("owner_id") == subject


def _to_response(item: dict) -> dict:
    """OWASP API3: allowlist response fields; never serialize the raw record."""
    return {
        "id": item["id"],
        "name": item["name"],
        "createdAt": item.get("created_at"),
    }


def lambda_handler(event, _context):
    claims = event["requestContext"]["authorizer"]["jwt"]["claims"]
    subject = claims["sub"]

    item_id = event["pathParameters"]["id"]
    item = _load_item(item_id)

    if item is None:
        return {"statusCode": 404, "body": json.dumps({"error": "not found"})}

    # API1 BOLA: deny by default unless the caller owns the object.
    if not _authorized(subject, item):
        return {"statusCode": 403, "body": json.dumps({"error": "forbidden"})}

    return {"statusCode": 200, "body": json.dumps(_to_response(item))}


def _load_item(item_id: str):
    # Placeholder data access. In real code use a parameterized query and
    # scope it to the caller to defend BOLA at the data layer too.
    return {
        "id": item_id,
        "name": "example",
        "owner_id": "demo-subject",
        "created_at": "2026-01-01T00:00:00Z",
    }
