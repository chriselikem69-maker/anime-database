#!/usr/bin/env python3
"""
ingest_jikan.py — pull anime, character, and episode data from the Jikan API
(https://docs.api.jikan.moe/, a free wrapper around MyAnimeList) into a local
SQLite database.

Usage:
    python anime_database/ingest_jikan.py --pages 20 --episode-pages 5

Jikan's public rate limit is 3 requests/second and 60 requests/minute, so this
script self-throttles rather than assuming you've set up your own API key or
proxy.

Data source: every row this script writes ultimately comes from MyAnimeList,
via the Jikan API. That provenance is also written into each row (see the
`source` column on every table) so downstream consumers — including the
website's "AniBot" feature — can state where their information came from.
"""

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path

import requests

JIKAN_BASE = "https://api.jikan.moe/v4"
SOURCE_LABEL = "MyAnimeList (via Jikan API)"
USER_AGENT = "anikiosk-anime-library-ingest/1.0 (+https://api.jikan.moe/v4)"


class RateLimiter:
    """Keeps requests under Jikan's public limits: 3 req/sec, 60 req/min."""

    def __init__(self, per_second=3, per_minute=60):
        self.per_second = per_second
        self.per_minute = per_minute
        self._second_hits = []
        self._minute_hits = []

    def wait(self):
        now = time.monotonic()
        self._second_hits = [t for t in self._second_hits if now - t < 1.0]
        self._minute_hits = [t for t in self._minute_hits if now - t < 60.0]

        if len(self._second_hits) >= self.per_second:
            time.sleep(1.0 - (now - self._second_hits[0]) + 0.02)
        if len(self._minute_hits) >= self.per_minute:
            sleep_for = 60.0 - (now - self._minute_hits[0]) + 0.5
            if sleep_for > 0:
                print(f"  … pausing {sleep_for:.0f}s to respect Jikan's per-minute limit", file=sys.stderr)
                time.sleep(sleep_for)

        hit_time = time.monotonic()
        self._second_hits.append(hit_time)
        self._minute_hits.append(hit_time)


RATE_LIMITER = RateLimiter()


def jikan_get(path, params=None, max_retries=5):
    """GET a Jikan endpoint with rate-limiting, retry-on-429, and basic backoff."""
    url = f"{JIKAN_BASE}/{path.lstrip('/')}"
    headers = {"User-Agent": USER_AGENT}
    backoff = 2.0

    for attempt in range(1, max_retries + 1):
        RATE_LIMITER.wait()
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=20)
        except requests.RequestException as exc:
            print(f"  ! network error on {url} (attempt {attempt}/{max_retries}): {exc}", file=sys.stderr)
            time.sleep(backoff)
            backoff *= 2
            continue

        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 404:
            return None
        if resp.status_code == 429:
            print(f"  ! rate-limited by Jikan, backing off {backoff:.0f}s", file=sys.stderr)
            time.sleep(backoff)
            backoff *= 2
            continue

        print(f"  ! unexpected status {resp.status_code} on {url}: {resp.text[:200]}", file=sys.stderr)
        time.sleep(backoff)
        backoff *= 2

    print(f"  ! giving up on {url} after {max_retries} attempts", file=sys.stderr)
    return None


SCHEMA = """
CREATE TABLE IF NOT EXISTS anime (
    mal_id      INTEGER PRIMARY KEY,
    title       TEXT NOT NULL,
    title_japanese TEXT,
    type        TEXT,
    episodes    INTEGER,
    score       REAL,
    status      TEXT,
    aired_from  TEXT,
    aired_to    TEXT,
    aired_string TEXT,
    synopsis    TEXT,
    genres      TEXT,      -- JSON array of genre names
    image_url   TEXT,
    source      TEXT NOT NULL,
    fetched_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS characters (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    anime_mal_id    INTEGER NOT NULL REFERENCES anime(mal_id),
    character_mal_id INTEGER NOT NULL,
    name            TEXT NOT NULL,
    role            TEXT,
    image_url       TEXT,
    source          TEXT NOT NULL,
    fetched_at      INTEGER NOT NULL,
    UNIQUE(anime_mal_id, character_mal_id)
);

CREATE TABLE IF NOT EXISTS episodes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    anime_mal_id    INTEGER NOT NULL REFERENCES anime(mal_id),
    episode_number  INTEGER NOT NULL,
    title           TEXT,
    aired           TEXT,
    filler          INTEGER,
    recap           INTEGER,
    source          TEXT NOT NULL,
    fetched_at      INTEGER NOT NULL,
    UNIQUE(anime_mal_id, episode_number)
);

CREATE TABLE IF NOT EXISTS ingest_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at      INTEGER NOT NULL,
    pages       INTEGER NOT NULL,
    episode_pages INTEGER NOT NULL,
    anime_count INTEGER NOT NULL,
    character_count INTEGER NOT NULL,
    episode_count INTEGER NOT NULL
);
"""


def get_db(path):
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.executescript(SCHEMA)
    return conn


def upsert_anime(conn, entry):
    now = int(time.time())
    genres = json.dumps([g["name"] for g in (entry.get("genres") or [])] +
                         [t["name"] for t in (entry.get("themes") or [])])
    conn.execute(
        """
        INSERT INTO anime (mal_id, title, title_japanese, type, episodes, score, status,
                            aired_from, aired_to, aired_string, synopsis, genres, image_url,
                            source, fetched_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(mal_id) DO UPDATE SET
            title=excluded.title, title_japanese=excluded.title_japanese, type=excluded.type,
            episodes=excluded.episodes, score=excluded.score, status=excluded.status,
            aired_from=excluded.aired_from, aired_to=excluded.aired_to,
            aired_string=excluded.aired_string, synopsis=excluded.synopsis,
            genres=excluded.genres, image_url=excluded.image_url, fetched_at=excluded.fetched_at
        """,
        (
            entry["mal_id"],
            entry.get("title"),
            entry.get("title_japanese"),
            entry.get("type"),
            entry.get("episodes"),
            entry.get("score"),
            entry.get("status"),
            (entry.get("aired") or {}).get("from"),
            (entry.get("aired") or {}).get("to"),
            (entry.get("aired") or {}).get("string"),
            entry.get("synopsis"),
            genres,
            (entry.get("images") or {}).get("jpg", {}).get("image_url"),
            SOURCE_LABEL,
            now,
        ),
    )
    conn.commit()


def ingest_characters(conn, anime_id):
    data = jikan_get(f"anime/{anime_id}/characters")
    if not data or "data" not in data:
        return 0
    now = int(time.time())
    count = 0
    for c in data["data"]:
        ch = c.get("character") or {}
        conn.execute(
            """
            INSERT INTO characters (anime_mal_id, character_mal_id, name, role, image_url, source, fetched_at)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(anime_mal_id, character_mal_id) DO UPDATE SET
                name=excluded.name, role=excluded.role, image_url=excluded.image_url, fetched_at=excluded.fetched_at
            """,
            (
                anime_id,
                ch.get("mal_id"),
                ch.get("name"),
                c.get("role"),
                (ch.get("images") or {}).get("jpg", {}).get("image_url"),
                SOURCE_LABEL,
                now,
            ),
        )
        count += 1
    conn.commit()
    return count


def ingest_episodes(conn, anime_id, episode_pages):
    now = int(time.time())
    total = 0
    for page in range(1, episode_pages + 1):
        data = jikan_get(f"anime/{anime_id}/episodes", params={"page": page})
        if not data or not data.get("data"):
            break
        for ep in data["data"]:
            conn.execute(
                """
                INSERT INTO episodes (anime_mal_id, episode_number, title, aired, filler, recap, source, fetched_at)
                VALUES (?,?,?,?,?,?,?,?)
                ON CONFLICT(anime_mal_id, episode_number) DO UPDATE SET
                    title=excluded.title, aired=excluded.aired, filler=excluded.filler,
                    recap=excluded.recap, fetched_at=excluded.fetched_at
                """,
                (
                    anime_id,
                    ep.get("mal_id"),
                    ep.get("title"),
                    ep.get("aired"),
                    1 if ep.get("filler") else 0,
                    1 if ep.get("recap") else 0,
                    SOURCE_LABEL,
                    now,
                ),
            )
            total += 1
        conn.commit()
        pagination = data.get("pagination") or {}
        if not pagination.get("has_next_page"):
            break
    return total


def run(pages, episode_pages, db_path, skip_existing):
    conn = get_db(db_path)
    anime_count = 0
    character_count = 0
    episode_count = 0

    for page in range(1, pages + 1):
        print(f"[page {page}/{pages}] fetching top anime list…")
        data = jikan_get("top/anime", params={"page": page})
        if not data or not data.get("data"):
            print(f"  ! no data returned for page {page}, stopping pagination")
            break

        for entry in data["data"]:
            anime_id = entry["mal_id"]
            title = entry.get("title", f"#{anime_id}")

            if skip_existing:
                exists = conn.execute("SELECT 1 FROM anime WHERE mal_id=?", (anime_id,)).fetchone()
                if exists:
                    print(f"  - {title}: already in database, skipping")
                    continue

            upsert_anime(conn, entry)
            anime_count += 1
            print(f"  + {title} (id {anime_id})")

            n_chars = ingest_characters(conn, anime_id)
            character_count += n_chars
            print(f"      characters: {n_chars}")

            n_eps = ingest_episodes(conn, anime_id, episode_pages)
            episode_count += n_eps
            print(f"      episodes:   {n_eps}")

        pagination = data.get("pagination") or {}
        if not pagination.get("has_next_page"):
            print("  reached the last page of results early, stopping.")
            break

    conn.execute(
        "INSERT INTO ingest_log (run_at, pages, episode_pages, anime_count, character_count, episode_count) "
        "VALUES (?,?,?,?,?,?)",
        (int(time.time()), pages, episode_pages, anime_count, character_count, episode_count),
    )
    conn.commit()
    conn.close()

    print("\nDone.")
    print(f"  anime added/updated:      {anime_count}")
    print(f"  characters added/updated: {character_count}")
    print(f"  episodes added/updated:   {episode_count}")
    print(f"  database file:            {db_path}")
    print(f"  source of record:         {SOURCE_LABEL}")


def parse_args():
    p = argparse.ArgumentParser(description="Ingest anime/character/episode data from the Jikan API into SQLite.")
    p.add_argument("--pages", type=int, default=5,
                    help="How many pages of the top-anime list to walk (25 titles/page). Default: 5")
    p.add_argument("--episode-pages", type=int, default=1,
                    help="How many pages of episodes to pull per anime (100 episodes/page). Default: 1")
    p.add_argument("--db", type=str, default=str(Path(__file__).parent / "anime.db"),
                    help="Path to the SQLite database file to create/update.")
    p.add_argument("--skip-existing", action="store_true",
                    help="Skip anime already present in the database instead of refreshing them.")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.pages < 1 or args.episode_pages < 0:
        print("error: --pages must be >=1 and --episode-pages must be >=0", file=sys.stderr)
        sys.exit(1)
    run(args.pages, args.episode_pages, args.db, args.skip_existing)
