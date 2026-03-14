"""
Tests for the telemetry Lambda handler.

Tests routing, auth, input validation, and response format.
DynamoDB calls are mocked — these are unit tests, not integration tests.
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Set env vars before importing handler
os.environ["EVENTS_TABLE"] = "test-events"
os.environ["HEARTBEATS_TABLE"] = "test-heartbeats"
os.environ["API_KEY"] = "test-key"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import handler  # noqa: E402


def _make_event(method, path, body=None, headers=None, params=None):
    """Build a minimal API Gateway event."""
    ev = {
        "httpMethod": method,
        "path": path,
        "headers": headers or {},
        "queryStringParameters": params or {},
    }
    if body is not None:
        ev["body"] = json.dumps(body) if isinstance(body, dict) else body
    return ev


def _auth_headers():
    return {"Authorization": "Bearer test-key"}


class TestRouting(unittest.TestCase):
    def test_unknown_route_returns_404(self):
        event = _make_event("GET", "/nonexistent")
        resp = handler.handler(event, None)
        self.assertEqual(resp["statusCode"], 404)

    def test_health_returns_200(self):
        event = _make_event("GET", "/health")
        resp = handler.handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["status"], "ok")


class TestAuth(unittest.TestCase):
    def test_post_events_requires_auth(self):
        event = _make_event("POST", "/events", body={"events": []})
        resp = handler.handler(event, None)
        self.assertEqual(resp["statusCode"], 401)

    def test_post_events_rejects_bad_key(self):
        event = _make_event("POST", "/events",
                            body={"events": []},
                            headers={"Authorization": "Bearer wrong"})
        resp = handler.handler(event, None)
        self.assertEqual(resp["statusCode"], 401)

    def test_post_heartbeat_requires_auth(self):
        event = _make_event("POST", "/heartbeat", body={})
        resp = handler.handler(event, None)
        self.assertEqual(resp["statusCode"], 401)


class TestPostEvents(unittest.TestCase):
    @patch("handler._get_dynamodb")
    def test_accepts_valid_events(self, mock_get_dynamo):
        mock_dynamo = MagicMock()
        mock_get_dynamo.return_value = mock_dynamo
        mock_table = MagicMock()
        mock_dynamo.Table.return_value = mock_table
        mock_batch = MagicMock()
        mock_table.batch_writer.return_value.__enter__ = lambda s: mock_batch
        mock_table.batch_writer.return_value.__exit__ = MagicMock(return_value=False)

        event = _make_event("POST", "/events",
                            body={
                                "session_id": "sess-1",
                                "events": [
                                    {"event_type": 256, "severity": 2, "pid": 100},
                                    {"event_type": 1, "severity": 0, "pid": 200},
                                ],
                            },
                            headers=_auth_headers())

        resp = handler.handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["accepted"], 2)

    def test_rejects_invalid_json(self):
        event = _make_event("POST", "/events",
                            headers=_auth_headers())
        event["body"] = "not json{"
        resp = handler.handler(event, None)
        self.assertEqual(resp["statusCode"], 400)

    def test_rejects_non_array_events(self):
        event = _make_event("POST", "/events",
                            body={"events": "not an array"},
                            headers=_auth_headers())
        resp = handler.handler(event, None)
        self.assertEqual(resp["statusCode"], 400)


class TestPostHeartbeat(unittest.TestCase):
    @patch("handler._get_dynamodb")
    def test_accepts_valid_heartbeat(self, mock_get_dynamo):
        mock_dynamo = MagicMock()
        mock_get_dynamo.return_value = mock_dynamo
        mock_table = MagicMock()
        mock_dynamo.Table.return_value = mock_table

        event = _make_event("POST", "/heartbeat",
                            body={
                                "hostname": "graviton-dev",
                                "game_pid": 1234,
                                "events_since_last": 5,
                                "severity_max": 2,
                            },
                            headers=_auth_headers())

        resp = handler.handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["action"], 0)  # CONTINUE
        self.assertIn("sig_version", body)


class TestGetEvents(unittest.TestCase):
    @patch("handler._get_dynamodb")
    def test_query_with_session_id(self, mock_get_dynamo):
        mock_dynamo = MagicMock()
        mock_get_dynamo.return_value = mock_dynamo
        mock_table = MagicMock()
        mock_dynamo.Table.return_value = mock_table
        mock_table.query.return_value = {"Items": [{"event_type": 1}]}

        event = _make_event("GET", "/events",
                            params={"session_id": "sess-1", "limit": "10"})

        resp = handler.handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["count"], 1)

    @patch("handler._get_dynamodb")
    def test_scan_without_session_id(self, mock_get_dynamo):
        mock_dynamo = MagicMock()
        mock_get_dynamo.return_value = mock_dynamo
        mock_table = MagicMock()
        mock_dynamo.Table.return_value = mock_table
        mock_table.scan.return_value = {"Items": []}

        event = _make_event("GET", "/events")
        resp = handler.handler(event, None)
        self.assertEqual(resp["statusCode"], 200)


if __name__ == "__main__":
    unittest.main()
