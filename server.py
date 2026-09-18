#!/usr/bin/env python3
"""
server.py — serves the local anime.db SQLite database (built by ingest_jikan.py)
over a small JSON HTTP API, shaped to match what the Anikiosk website expects
from the live Jikan API. No third-party dependencies required.

Run:
    python anime_database/server.py --db anime_database/anime.db --port 8787

Then open the website. It checks http://localhost:8787/api/status on load —
if this server is running, the Library, Character browser, and AniBot all
read from your local ingested database instead of calling the live Jikan API.
If the server isn't running (or the database is empty), the site falls back
to the live API automatically, so nothing breaks either way.

Note on CORS: the website is a local HTML file (or an artifact preview), a
different origin than this server, so every response includes
Access-Control-Allow-Origin: * to allow that cross-origin fetch.
"""

import argparse
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

DB_PATH = "anime_database/anime.db"
PAGE_SIZE = 25


def row_to_anime(row):
    genres = json.loads(row["genres"]) if row["genres"] else []
    return {
        "mal_id": row["mal_id"],
        "title": row["title"],
        "title_japanese": row["title_japanese"],
        "type": row["type"],
        "episodes": row["episodes"],
        "score": row["score"],
        "status": row["status"],
        "year": int(row["aired_from"][:4]) if row["aired_from"] else None,
        "aired": {"from": row["aired_from"], "to": row["aired_to"], "string": row["aired_string"]},
        "synopsis": row["synopsis"],
        "genres": [{"name": g} for g in genres],
        "themes": [],
        "images": {"jpg": {"image_url": row["image_url"], "large_image_url": row["image_url"]}},
        "source": row["source"],
    }


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # quiet by default; comment out to debug requests

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        try:
            conn = get_conn()
            parts = path.strip("/").split("/")  # e.g. ['api','anime','5114','characters']

            if path == "/api/status":
                count = conn.execute("SELECT COUNT(*) c FROM anime").fetchone()["c"]
                self._send_json({"ok": True, "anime_count": count})

            elif path == "/api/top-anime":
                page = int(qs.get("page", ["1"])[0])
                offset = (page - 1) * PAGE_SIZE
                rows = conn.execute(
                    "SELECT * FROM anime ORDER BY (score IS NULL), score DESC LIMIT ? OFFSET ?",
                    (PAGE_SIZE, offset),
                ).fetchall()
                self._send_json([row_to_anime(r) for r in rows])

            elif path == "/api/search":
                q = qs.get("q", [""])[0]
                rows = conn.execute(
                    "SELECT * FROM anime WHERE title LIKE ? OR title_japanese LIKE ? "
                    "ORDER BY (score IS NULL), score DESC LIMIT 15",
                    (f"%{q}%", f"%{q}%"),
                ).fetchall()
                self._send_json([row_to_anime(r) for r in rows])

            elif path == "/api/top-characters":
                limit = int(qs.get("limit", ["10"])[0])
                rows = conn.execute(
                    """
                    SELECT c.*, a.score AS anime_score FROM characters c
                    JOIN anime a ON a.mal_id = c.anime_mal_id
                    WHERE c.role = 'Main'
                    ORDER BY (a.score IS NULL), a.score DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
                self._send_json([
                    {
                        "mal_id": r["character_mal_id"],
                        "name": r["name"],
                        "images": {"jpg": {"image_url": r["image_url"]}},
                        "about": None,
                    }
                    for r in rows
                ])

            elif len(parts) == 4 and parts[0] == "api" and parts[1] == "anime" and parts[3] == "characters":
                anime_id = int(parts[2])
                rows = conn.execute(
                    "SELECT * FROM characters WHERE anime_mal_id=?", (anime_id,)
                ).fetchall()
                self._send_json([
                    {
                        "character": {
                            "mal_id": r["character_mal_id"],
                            "name": r["name"],
                            "images": {"jpg": {"image_url": r["image_url"]}},
                        },
                        "role": r["role"],
                    }
                    for r in rows
                ])

            elif len(parts) == 3 and parts[0] == "api" and parts[1] == "anime":
                anime_id = int(parts[2])
                row = conn.execute("SELECT * FROM anime WHERE mal_id=?", (anime_id,)).fetchone()
                if not row:
                    self._send_json({"error": "not found"}, 404)
                else:
                    self._send_json(row_to_anime(row))

            else:
                self._send_json({"error": "not found", "path": path}, 404)

            conn.close()
        except Exception as exc:
            self._send_json({"error": str(exc)}, 500)


def main():
    global DB_PATH
    p = argparse.ArgumentParser(description="Serve the ingested anime.db over a local JSON API.")
    p.add_argument("--db", default=DB_PATH, help="Path to the SQLite database created by ingest_jikan.py")
    p.add_argument("--port", type=int, default=8787)
    args = p.parse_args()
    DB_PATH = args.db

    server = ThreadingHTTPServer(("localhost", args.port), Handler)
    print(f"Serving {DB_PATH} at http://localhost:{args.port}")
    print("Point the website at this by just leaving it running — it auto-detects the server.")
    print("Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
