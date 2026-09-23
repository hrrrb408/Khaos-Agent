import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class TaskHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/task":
            payload = {"status": "open", "count": 1}
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    HTTPServer(("127.0.0.1", port), TaskHandler).serve_forever()
