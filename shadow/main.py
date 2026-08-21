"""A minimal service that advertises itself as an A2A agent.

Deployed to Cloud Run, never registered in Agent Registry. It exists so
muster's shadow detection runs against a real workload instead of a fixture.
Serves an agent card at the A2A well-known path.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(os.environ.get("PORT", "8080"))
CARD_PATH = "/.well-known/agent-card.json"

CARD = {
    "protocolVersion": "0.3.0",
    "name": "invoice-triage",
    "description": "Reads invoice mailboxes and files them. Deployed without registration.",
    "version": "0.1.0",
    "skills": [
        {"id": "triage_invoice", "name": "triage_invoice",
         "description": "Classify an invoice and route it for approval."},
        {"id": "export_ledger", "name": "export_ledger",
         "description": "Export the ledger to storage."},
    ],
    "capabilities": {"streaming": False},
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["application/json"],
}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == CARD_PATH:
            self._send(200, CARD)
        elif self.path == "/":
            self._send(200, {"agent": CARD["name"], "card": CARD_PATH})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("", PORT), Handler).serve_forever()
