#!/usr/bin/env python3
"""
ingest_anilist.py — pull anime + character data from AniList's public
GraphQL API (https://anilist.co, docs at https://docs.anilist.co) as an
alternative to ingest_jikan.py, for whenever Jikan/MyAnimeList is having
one of its connectivity outages.

Writes into the exact same anime.db schema as ingest_jikan.py (anime,
characters, episodes tables), keyed by MyAnimeList ID — AniList exposes
each title's corresponding MAL id directly (idMal), so rows from this
script and rows from ingest_jikan.py land in the same table and upsert
against each other cleanly. Safe to use either script, or both, against
the same database.

Two honest differences from the Jikan version, worth knowing:
  - Scores are converted from AniList's 0-100 scale to MAL's 0-10 scale
    (divided by 10) to stay consistent with existing data and the site's
    display, which expects a 0-10 number.
  - AniList doesn't expose per-episode titles/air-dates the way Jikan's
    /episodes endpoint does — only a total episode count. This script
    leaves the episodes table alone entirely; the site doesn't currently
    render an episode-by-episode list anywhere, only the total count
    (which does get filled in), so this isn't a feature gap in practice.

No API key needed for this — AniList's public read queries are open.

Usage:
    python anime_database/ingest_anilist.py --pages 20
"""

import argparse
import json
import re
import sqlite3
import sys
import time
from pathlib import Path

import requests

ANILIST_URL = "https://graphql.anilist.co"
SOURCE_LABEL = "AniList (anilist.co)"
PER_PAGE = 25

QUERY = """
query ($page: Int, $perPage: Int) {
  Page(page: $page, perPage: $perPage) {
    pageInfo { hasNextPage }
    media(type: ANIME, sort: POPULARITY_DESC) {
      idMal
      title { romaji english native }
      format
      episodes
      averageScore
      status
      startDate { year month day }
      endDate { year month day }
      description(asHtml: false)
      genres
      coverImage { large }
      characters(sort: [ROLE, RELEVANCE], perPage: 12) {
        edges {
          role
          node { id name { full } image { large } }
        }
      }
    }
  }
}
"""

STATUS_MAP = {
    "FINISHED": "Finished Airing",
    "RELEASING": "Currently Airing",
    "NOT_YET_RELEASED": "Not yet aired",
    "CANCELLED": "Cancelled",
    "HIATUS": "On Hiatus",
}
FORMAT_MAP = {
    "TV": "TV", "TV_SHORT": "TV Short", "MOVIE": "Movie", "SPECIAL": "Special",
    "OVA": "OVA", "ONA": "ONA", "MUSIC": "Music",
}

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
    genres      TEXT,
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
"""


def get_db(path):
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    return conn


def strip_markup(text):
    if not text:
        return text
    text = re.sub(r"<[^>]+>", " ", text)          # stray <br>, <i>, etc.
    text = re.sub(r"[_*~]{1,3}", "", text)          # markdown emphasis chars
    text = re.sub(r"\s+", " ", text).strip()
    return re.sub(r"\s+([.,!?;:])", r"\1", text)     # no space before punctuation


def build_date(d):
    if not d or not d.get("year"):
        return None
    y, m, day = d["year"], d.get("month") or 1, d.get("day") or 1
    return f"{y:04d}-{m:02d}-{day:02d}"


def build_aired_string(start, end, status):
    s = start.get("year") if start else None
    e = end.get("year") if end else None
    if not s:
        return None
    if status == "RELEASING":
        return f"{s} to ?"
    if e and e != s:
        return f"{s} to {e}"
    return str(s)


def anilist_post(query, variables, max_retries=6):
    backoff = 2.0
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.post(
                ANILIST_URL, json={"query": query, "variables": variables}, timeout=20
            )
        except requests.RequestException as exc:
            print(f"  ! network error (attempt {attempt}/{max_retries}): {exc}", file=sys.stderr)
            time.sleep(backoff)
            backoff *= 2
            continue

        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 429:
            retry_after = float(resp.headers.get("Retry-After", backoff))
            print(f"  ! rate-limited by AniList, waiting {retry_after:.0f}s", file=sys.stderr)
            time.sleep(retry_after)
            continue

        print(f"  ! unexpected status {resp.status_code}: {resp.text[:200]}", file=sys.stderr)
        time.sleep(backoff)
        backoff *= 2

    print(f"  ! giving up after {max_retries} attempts", file=sys.stderr)
    return None


def upsert_anime(conn, m):
    mal_id = m.get("idMal")
    if not mal_id:
        return False  # a handful of AniList entries have no MAL counterpart; skip, nothing to key on

    title = m["title"].get("english") or m["title"].get("romaji")
    score = (m["averageScore"] / 10) if m.get("averageScore") is not None else None
    now = int(time.time())

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
            mal_id, title, m["title"].get("native"), FORMAT_MAP.get(m.get("format"), m.get("format")),
            m.get("episodes"), score, STATUS_MAP.get(m.get("status"), m.get("status")),
            build_date(m.get("startDate")), build_date(m.get("endDate")),
            build_aired_string(m.get("startDate"), m.get("endDate"), m.get("status")),
            strip_markup(m.get("description")), json.dumps(m.get("genres") or []),
            (m.get("coverImage") or {}).get("large"), SOURCE_LABEL, now,
        ),
    )

    now = int(time.time())
    for edge in (m.get("characters") or {}).get("edges", []):
        node = edge.get("node") or {}
        conn.execute(
            """
            INSERT INTO characters (anime_mal_id, character_mal_id, name, role, image_url, source, fetched_at)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(anime_mal_id, character_mal_id) DO UPDATE SET
                name=excluded.name, role=excluded.role, image_url=excluded.image_url, fetched_at=excluded.fetched_at
            """,
            (
                mal_id, node.get("id"), (node.get("name") or {}).get("full"),
                edge.get("role"), (node.get("image") or {}).get("large"),
                SOURCE_LABEL, now,
            ),
        )
    return True


def run(pages, db_path, skip_existing):
    conn = get_db(db_path)
    anime_count = 0
    character_count = 0

    for page in range(1, pages + 1):
        print(f"[page {page}/{pages}] fetching from AniList…")
        data = anilist_post(QUERY, {"page": page, "perPage": PER_PAGE})
        if not data or "errors" in data:
            print(f"  ! AniList returned an error: {data.get('errors') if data else 'no response'}", file=sys.stderr)
            break
        media_list = (data.get("data") or {}).get("Page", {}).get("media", [])
        if not media_list:
            print("  no more results, stopping.")
            break

        for m in media_list:
            mal_id = m.get("idMal")
            title = m["title"].get("english") or m["title"].get("romaji") or f"AniList #{m.get('id')}"
            if skip_existing and mal_id:
                exists = conn.execute("SELECT 1 FROM anime WHERE mal_id=?", (mal_id,)).fetchone()
                if exists:
                    print(f"  - {title}: already in database, skipping")
                    continue
            if upsert_anime(conn, m):
                n_chars = len((m.get("characters") or {}).get("edges", []))
                anime_count += 1
                character_count += n_chars
                print(f"  + {title} (mal_id {mal_id}) — {n_chars} characters")
            else:
                print(f"  - {title}: no MyAnimeList id on AniList, skipped")
        conn.commit()

        has_next = ((data.get("data") or {}).get("Page", {}).get("pageInfo") or {}).get("hasNextPage")
        if not has_next:
            print("  reached the last page of results early, stopping.")
            break

    conn.close()
    print("\nDone.")
    print(f"  anime added/updated:      {anime_count}")
    print(f"  characters added/updated: {character_count}")
    print(f"  database file:            {db_path}")
    print(f"  source of record:         {SOURCE_LABEL}")
    print("  note: episode-level data was NOT touched by this script (see the module docstring).")


def parse_args():
    p = argparse.ArgumentParser(description="Ingest anime/character data from AniList into SQLite.")
    p.add_argument("--pages", type=int, default=5,
                    help=f"How many pages of {PER_PAGE} titles each to fetch, sorted by popularity. Default: 5")
    p.add_argument("--db", type=str, default=str(Path(__file__).parent / "anime.db"),
                    help="Path to the SQLite database file to create/update.")
    p.add_argument("--skip-existing", action="store_true",
                    help="Skip anime already present in the database instead of refreshing them.")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.pages < 1:
        print("error: --pages must be >=1", file=sys.stderr)
        sys.exit(1)
    run(args.pages, args.db, args.skip_existing)
