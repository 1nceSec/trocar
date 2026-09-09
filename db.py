import aiosqlite
from config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    phase TEXT DEFAULT 'init',
    cookie TEXT DEFAULT '',
    cookie_b TEXT DEFAULT '',
    scope_notes TEXT DEFAULT '',
    group_name TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP,
    turns INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    report_path TEXT DEFAULT '',
    no_finding_streak INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    vuln_type TEXT NOT NULL,
    endpoint TEXT DEFAULT '',
    poc TEXT DEFAULT '',
    description TEXT DEFAULT '',
    chain TEXT DEFAULT '',
    verified INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    phase TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS blackboard (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    partition TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);
"""


async def init_db():
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.executescript(SCHEMA)
        try:
            await conn.execute("ALTER TABLE sessions ADD COLUMN group_name TEXT DEFAULT ''")
        except Exception:
            pass
        await conn.commit()


async def get_db():
    conn = await aiosqlite.connect(DB_PATH)
    conn.row_factory = aiosqlite.Row
    return conn


async def create_session(target: str, cookie: str = "", cookie_b: str = "", scope_notes: str = "", group_name: str = "") -> int:
    async with aiosqlite.connect(DB_PATH) as conn:
        cur = await conn.execute(
            "INSERT INTO sessions (target, cookie, cookie_b, scope_notes, group_name) VALUES (?, ?, ?, ?, ?)",
            (target, cookie, cookie_b, scope_notes, group_name),
        )
        await conn.commit()
        return cur.lastrowid


async def update_session(sid: int, **kwargs):
    if not kwargs:
        return
    cols = ", ".join(f"{k}=?" for k in kwargs)
    vals = list(kwargs.values()) + [sid]
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(f"UPDATE sessions SET {cols}, updated_at=CURRENT_TIMESTAMP WHERE id=?", vals)
        await conn.commit()


async def get_session(sid: int) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute("SELECT * FROM sessions WHERE id=?", (sid,))
        row = await cur.fetchone()
        return dict(row) if row else None


async def list_sessions(search: str = "", group: str = "") -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        q = "SELECT * FROM sessions WHERE 1=1"
        params: list = []
        if search:
            q += " AND target LIKE ?"
            params.append(f"%{search}%")
        if group:
            q += " AND group_name=?"
            params.append(group)
        q += " ORDER BY id DESC"
        cur = await conn.execute(q, params)
        sessions = [dict(r) for r in await cur.fetchall()]
        for s in sessions:
            cur2 = await conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM findings WHERE session_id=? GROUP BY severity",
                (s["id"],),
            )
            s["severity_summary"] = {row[0]: row[1] for row in await cur2.fetchall()}
        return sessions


async def list_groups() -> list[str]:
    async with aiosqlite.connect(DB_PATH) as conn:
        cur = await conn.execute(
            "SELECT DISTINCT group_name FROM sessions WHERE group_name != '' ORDER BY group_name"
        )
        return [row[0] for row in await cur.fetchall()]


async def add_finding(session_id: int, severity: str, title: str, vuln_type: str,
                      endpoint: str = "", poc: str = "", description: str = "", chain: str = "") -> int:
    async with aiosqlite.connect(DB_PATH) as conn:
        cur = await conn.execute(
            "INSERT INTO findings (session_id, severity, title, vuln_type, endpoint, poc, description, chain) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (session_id, severity, title, vuln_type, endpoint, poc, description, chain),
        )
        await conn.execute(
            "UPDATE sessions SET findings_count = findings_count + 1, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (session_id,),
        )
        await conn.commit()
        return cur.lastrowid


async def get_findings(session_id: int) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute("SELECT * FROM findings WHERE session_id=? ORDER BY id", (session_id,))
        return [dict(r) for r in await cur.fetchall()]


async def add_log(session_id: int, role: str, content: str, phase: str = ""):
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            "INSERT INTO logs (session_id, role, content, phase) VALUES (?, ?, ?, ?)",
            (session_id, role, content, phase),
        )
        await conn.commit()


async def get_logs(session_id: int, after_id: int = 0, limit: int = 0) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        if limit > 0:
            cur = await conn.execute(
                "SELECT * FROM logs WHERE session_id=? AND id>? ORDER BY id LIMIT ?",
                (session_id, after_id, limit),
            )
        else:
            cur = await conn.execute(
                "SELECT * FROM logs WHERE session_id=? AND id>? ORDER BY id",
                (session_id, after_id),
            )
        return [dict(r) for r in await cur.fetchall()]


async def delete_session(sid: int):
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute("DELETE FROM blackboard WHERE session_id=?", (sid,))
        await conn.execute("DELETE FROM logs WHERE session_id=?", (sid,))
        await conn.execute("DELETE FROM findings WHERE session_id=?", (sid,))
        await conn.execute("DELETE FROM sessions WHERE id=?", (sid,))
        await conn.commit()


# ─── Blackboard CRUD ────────────────────────────────────────

PARTITIONS = ("attack_surfaces", "verified_findings", "pending_hypotheses", "exploits", "failure_records")


async def bb_write(session_id: int, partition: str, key: str, value: str = "", status: str = "active") -> int:
    async with aiosqlite.connect(DB_PATH) as conn:
        existing = await conn.execute(
            "SELECT id FROM blackboard WHERE session_id=? AND partition=? AND key=?",
            (session_id, partition, key),
        )
        row = await existing.fetchone()
        if row:
            await conn.execute(
                "UPDATE blackboard SET value=?, status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (value, status, row[0]),
            )
            await conn.commit()
            return row[0]
        cur = await conn.execute(
            "INSERT INTO blackboard (session_id, partition, key, value, status) VALUES (?, ?, ?, ?, ?)",
            (session_id, partition, key, value, status),
        )
        await conn.commit()
        return cur.lastrowid


async def bb_read(session_id: int, partition: str = "", status: str = "") -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        q = "SELECT * FROM blackboard WHERE session_id=?"
        params: list = [session_id]
        if partition:
            q += " AND partition=?"
            params.append(partition)
        if status:
            q += " AND status=?"
            params.append(status)
        q += " ORDER BY updated_at DESC"
        cur = await conn.execute(q, params)
        return [dict(r) for r in await cur.fetchall()]


async def bb_summary(session_id: int) -> dict:
    async with aiosqlite.connect(DB_PATH) as conn:
        result = {}
        for p in PARTITIONS:
            cur = await conn.execute(
                "SELECT COUNT(*) FROM blackboard WHERE session_id=? AND partition=? AND status='active'",
                (session_id, p),
            )
            row = await cur.fetchone()
            result[p] = row[0] if row else 0
        return result
