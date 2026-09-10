#!/usr/bin/env python3
"""
merge_import.py — merge anime data from another SQLite database into this
project's anime.db, upserting by MyAnimeList id (mal_id) so it's always
safe to re-run.

Two source shapes are handled automatically:
  - "flat"       — the same shape this project's own ingest_jikan.py produces
                   (tables: anime, characters, episodes). Straightforward
                   row-for-row upsert.
  - "normalized" — a richer, fully normalized schema some other tools export
                   (tables: anime, title, genre, anime_genre, character,
                   anime_character, episode, ...), detected by the presence
                   of an anime_genre table. Genres/themes get joined and
                   flattened into this project's genres JSON column;
                   characters and episodes get mapped field-for-field.

The target database is opened read-write and created fresh (with this
project's schema) if it doesn't exist yet. The source is opened strictly
read-only — this script never touches the file you're merging from.

Usage:
    python anime_database/merge_import.py --source other.db --target anime_database/anime.db
"""

import argparse
import json
import sqlite3
import time

SOURCE_LABEL = "MyAnimeList (via Jikan API)"

TARGET_SCHEMA = """
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


def open_target(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(TARGET_SCHEMA)
    conn.commit()
    return conn


def open_source_readonly(path):
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def detect_shape(conn):
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "anime_genre" in tables or "anime_character" in tables:
        return "normalized"
    return "flat"


def upsert_anime(conn, mal_id, title, title_japanese, type_, episodes, score, status,
                  aired_from, aired_to, aired_string, synopsis, genres_list, image_url):
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
        (mal_id, title, title_japanese, type_, episodes, score, status, aired_from, aired_to,
         aired_string, synopsis, json.dumps(genres_list or []), image_url, SOURCE_LABEL, now),
    )


def upsert_character(conn, anime_mal_id, character_mal_id, name, role, image_url):
    now = int(time.time())
    conn.execute(
        """
        INSERT INTO characters (anime_mal_id, character_mal_id, name, role, image_url, source, fetched_at)
        VALUES (?,?,?,?,?,?,?)
        ON CONFLICT(anime_mal_id, character_mal_id) DO UPDATE SET
            name=excluded.name, role=excluded.role, image_url=excluded.image_url, fetched_at=excluded.fetched_at
        """,
        (anime_mal_id, character_mal_id, name, role, image_url, SOURCE_LABEL, now),
    )


def upsert_episode(conn, anime_mal_id, episode_number, title, aired, filler, recap):
    now = int(time.time())
    conn.execute(
        """
        INSERT INTO episodes (anime_mal_id, episode_number, title, aired, filler, recap, source, fetched_at)
        VALUES (?,?,?,?,?,?,?,?)
        ON CONFLICT(anime_mal_id, episode_number) DO UPDATE SET
            title=excluded.title, aired=excluded.aired, filler=excluded.filler,
            recap=excluded.recap, fetched_at=excluded.fetched_at
        """,
        (anime_mal_id, int(episode_number), title, aired, 1 if filler else 0, 1 if recap else 0,
         SOURCE_LABEL, now),
    )


def merge_flat(src, dst):
    counts = {"anime": 0, "characters": 0, "episodes": 0}
    for r in src.execute("SELECT * FROM anime"):
        genres = json.loads(r["genres"]) if r["genres"] else []
        upsert_anime(dst, r["mal_id"], r["title"], r["title_japanese"], r["type"], r["episodes"],
                     r["score"], r["status"], r["aired_from"], r["aired_to"], r["aired_string"],
                     r["synopsis"], genres, r["image_url"])
        counts["anime"] += 1
    for r in src.execute("SELECT * FROM characters"):
        upsert_character(dst, r["anime_mal_id"], r["character_mal_id"], r["name"], r["role"], r["image_url"])
        counts["characters"] += 1
    for r in src.execute("SELECT * FROM episodes"):
        upsert_episode(dst, r["anime_mal_id"], r["episode_number"], r["title"], r["aired"], r["filler"], r["recap"])
        counts["episodes"] += 1
    return counts


def merge_normalized(src, dst):
    counts = {"anime": 0, "characters": 0, "episodes": 0}

    # anime_id (source's internal PK) -> mal_id, needed to translate every
    # foreign key in the child tables below.
    id_map = {r["anime_id"]: r["mal_id"] for r in src.execute("SELECT anime_id, mal_id FROM anime") if r["mal_id"]}

    genre_rows = src.execute("""
        SELECT ag.anime_id, g.name FROM anime_genre ag JOIN genre g ON g.genre_id = ag.genre_id
        UNION ALL
        SELECT at.anime_id, t.name FROM anime_theme at JOIN theme t ON t.theme_id = at.theme_id
    """).fetchall()
    genres_by_anime = {}
    for r in genre_rows:
        genres_by_anime.setdefault(r["anime_id"], []).append(r["name"])

    aired_string_cache = {}
    for r in src.execute("SELECT anime_id, broadcast_string, aired_from, aired_to FROM anime"):
        if r["broadcast_string"]:
            aired_string_cache[r["anime_id"]] = r["broadcast_string"]
        elif r["aired_from"]:
            aired_string_cache[r["anime_id"]] = f"{r['aired_from'][:10]} to {(r['aired_to'] or '?')[:10]}"

    for r in src.execute("SELECT * FROM anime"):
        if not r["mal_id"]:
            continue  # can't upsert without the MAL id we key everything on
        title = r["title_english"] or r["title"]
        upsert_anime(
            dst, r["mal_id"], title, r["title_japanese"], r["type"], r["episodes"], r["score"],
            r["status"], r["aired_from"], r["aired_to"], aired_string_cache.get(r["anime_id"]),
            r["synopsis"], genres_by_anime.get(r["anime_id"], []), r["image_url"],
        )
        counts["anime"] += 1

    for r in src.execute("""
        SELECT ac.anime_id, ac.character_id, ac.role, c.name, c.image_url
        FROM anime_character ac JOIN character c ON c.character_id = ac.character_id
    """):
        mal_id = id_map.get(r["anime_id"])
        if not mal_id:
            continue
        # Source doesn't expose MAL's own character id, only its own internal
        # primary key — used here as a best-effort stand-in.
        upsert_character(dst, mal_id, r["character_id"], r["name"], r["role"], r["image_url"])
        counts["characters"] += 1

    for r in src.execute("SELECT * FROM episode"):
        mal_id = id_map.get(r["anime_id"])
        if not mal_id:
            continue
        upsert_episode(dst, mal_id, r["episode_number"], r["title"], r["aired"], r["filler"], r["recap"])
        counts["episodes"] += 1

    return counts


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", required=True, help="Path to the database to merge in (opened read-only)")
    p.add_argument("--target", required=True, help="Path to this project's anime.db (created if missing)")
    args = p.parse_args()

    src = open_source_readonly(args.source)
    dst = open_target(args.target)

    shape = detect_shape(src)
    print(f"Source schema detected: {shape}")

    before = dst.execute("SELECT COUNT(*) c FROM anime").fetchone()["c"]
    counts = merge_flat(src, dst) if shape == "flat" else merge_normalized(src, dst)
    dst.commit()
    after = dst.execute("SELECT COUNT(*) c FROM anime").fetchone()["c"]

    print(f"anime rows processed:      {counts['anime']}")
    print(f"character rows processed:  {counts['characters']}")
    print(f"episode rows processed:    {counts['episodes']}")
    print(f"target anime table:        {before} -> {after} rows")
    print(f"target database:           {args.target}")

    src.close()
    dst.close()


if __name__ == "__main__":
    main()
