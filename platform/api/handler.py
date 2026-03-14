"""
Owlbear telemetry receiver — AWS Lambda handler.

Endpoints:
  POST /events     — Receive batched detection events from daemon
  POST /heartbeat  — Receive daemon heartbeat, return action
  GET  /events     — Query recent events (for dashboard)
  GET  /health     — Health check
"""

import json
import os
import time
import uuid
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key

# DynamoDB tables (names from environment)
EVENTS_TABLE = os.environ.get("EVENTS_TABLE", "owlbear-events")
HEARTBEATS_TABLE = os.environ.get("HEARTBEATS_TABLE", "owlbear-heartbeats")
API_KEY = os.environ.get("API_KEY", "dev-key-change-in-prod")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-2")

# Lazy init — allows tests to mock before first use
_dynamodb = None


def _get_dynamodb():
    global _dynamodb
    if _dynamodb is None:
        _dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
    return _dynamodb


def _response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body, default=str),
    }


def _check_auth(event):
    """Validate API key from Authorization header."""
    headers = event.get("headers", {}) or {}
    auth = headers.get("authorization", headers.get("Authorization", ""))
    if auth != f"Bearer {API_KEY}":
        return _response(401, {"error": "unauthorized"})
    return None


def _float_to_decimal(obj):
    """Convert floats to Decimal for DynamoDB compatibility."""
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _float_to_decimal(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_float_to_decimal(i) for i in obj]
    return obj


def handle_post_events(event):
    """Receive batched events from the daemon."""
    auth_err = _check_auth(event)
    if auth_err:
        return auth_err

    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        return _response(400, {"error": "invalid json"})

    events = body.get("events", [])
    if not isinstance(events, list):
        return _response(400, {"error": "events must be an array"})

    session_id = body.get("session_id", "unknown")
    table = _get_dynamodb().Table(EVENTS_TABLE)

    written = 0
    with table.batch_writer() as batch:
        for ev in events:
            item = _float_to_decimal(ev)
            item["session_id"] = session_id
            item["event_id"] = str(uuid.uuid4())
            item["received_at"] = int(time.time())

            if "timestamp_ns" not in item:
                item["timestamp_ns"] = int(time.time() * 1e9)

            batch.put_item(Item=item)
            written += 1

    return _response(200, {"accepted": written})


def handle_post_heartbeat(event):
    """Receive daemon heartbeat, return action."""
    auth_err = _check_auth(event)
    if auth_err:
        return auth_err

    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        return _response(400, {"error": "invalid json"})

    instance_id = body.get("hostname", "unknown")
    table = _get_dynamodb().Table(HEARTBEATS_TABLE)

    item = _float_to_decimal(body)
    item["instance_id"] = instance_id
    item["received_at"] = int(time.time())
    # TTL: expire after 1 hour
    item["ttl"] = int(time.time()) + 3600

    table.put_item(Item=item)

    # Response: continue monitoring, no sig update
    response_body = {
        "action": 0,       # OWL_ACTION_CONTINUE
        "sig_version": 1,  # Current signature DB version
    }

    return _response(200, response_body)


def handle_get_events(event):
    """Query recent events for the dashboard."""
    params = event.get("queryStringParameters", {}) or {}
    session_id = params.get("session_id", None)
    limit = min(int(params.get("limit", "100")), 500)

    table = _get_dynamodb().Table(EVENTS_TABLE)

    if session_id:
        resp = table.query(
            KeyConditionExpression=Key("session_id").eq(session_id),
            Limit=limit,
            ScanIndexForward=False,  # newest first
        )
    else:
        # Scan (expensive, but acceptable for prototype dashboard)
        resp = table.scan(Limit=limit)

    items = resp.get("Items", [])
    return _response(200, {"events": items, "count": len(items)})


def handle_get_health(event):
    """Health check endpoint."""
    return _response(200, {
        "status": "ok",
        "service": "owlbear-telemetry",
        "timestamp": int(time.time()),
    })


# Route table
ROUTES = {
    ("POST", "/events"):    handle_post_events,
    ("POST", "/heartbeat"): handle_post_heartbeat,
    ("GET", "/events"):     handle_get_events,
    ("GET", "/health"):     handle_get_health,
}


def handler(event, context):
    """Lambda entry point — routes based on HTTP method and path."""
    method = event.get("httpMethod", event.get("requestContext", {})
                       .get("http", {}).get("method", "GET")).upper()
    path = event.get("path", event.get("rawPath", "/"))

    route_key = (method, path)
    route_handler = ROUTES.get(route_key)

    if route_handler is None:
        return _response(404, {"error": f"not found: {method} {path}"})

    try:
        return route_handler(event)
    except Exception as e:
        return _response(500, {"error": str(e)})
