from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import model_panel


class _Handler(BaseHTTPRequestHandler):
    request_body = None

    def do_POST(self):
        size = int(self.headers["Content-Length"])
        type(self).request_body = json.loads(self.rfile.read(size))
        content = json.dumps(
            {
                "summary": "ok",
                "missing_options": [],
                "current_defects": [],
                "top_next_experiments": [],
                "uncertainties": [],
            }
        )
        payload = json.dumps(
            {
                "choices": [{"message": {"content": content}}],
                "usage": {"total_tokens": 12},
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        return


class ModelPanelTest(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_local_provider_round_trip_and_result_redaction(self):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            config = temp / "config.json"
            output = temp / "results"
            config.write_text(
                json.dumps(
                    {
                        "providers": [
                            {
                                "name": "mock",
                                "enabled": True,
                                "url": (
                                    f"http://127.0.0.1:{self.server.server_port}"
                                    "/v1/chat/completions"
                                ),
                                "model": "mock-model",
                            }
                        ]
                    }
                )
            )
            result = model_panel.main(
                [
                    "--config",
                    str(config),
                    "--provider",
                    "mock",
                    "--context",
                    str(model_panel.ROOT / "README.md"),
                    "--output-dir",
                    str(output),
                ]
            )
            self.assertEqual(result, 0)
            record = json.loads(next(output.glob("*.json")).read_text())
            self.assertEqual(record["parsed"]["summary"], "ok")
            self.assertNotIn("url", record)
            self.assertEqual(_Handler.request_body["model"], "mock-model")

    def test_remote_provider_requires_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            config = temp / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "providers": [
                            {
                                "name": "remote",
                                "enabled": True,
                                "url": "https://example.com/v1/chat/completions",
                                "model": "example",
                            }
                        ]
                    }
                )
            )
            result = model_panel.main(
                [
                    "--config",
                    str(config),
                    "--context",
                    str(model_panel.ROOT / "README.md"),
                ]
            )
            self.assertEqual(result, 2)

    def test_json_extraction_handles_fences(self):
        self.assertEqual(
            model_panel._parsed_content('```json\n{"summary": "ok"}\n```'),
            {"summary": "ok"},
        )


if __name__ == "__main__":
    unittest.main()
