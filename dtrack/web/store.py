"""SQLite persistence layer for the DTrack web platform.

Single source of truth for:
  * whitelist / project multi-version records
  * the third-party component catalogue (``component``) and which
    whitelist/project versions reference each one (``component_usage``)
  * normalized vulnerabilities (``vulnerability``)

All access goes through :class:`Db`, which uses only the stdlib ``sqlite3``
module so the whole web stack stays dependency-free and offline-deployable.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

# 北京时间固定为 UTC+8（无夏令时）
_BEIJING_TZ = timezone(timedelta(hours=8))

# 漏洞严重程度（与前端 utils/severity.js 的 SEV_META 保持一致）
_SEV_KEYS = ("critical", "high", "medium", "low", "unknown")


def _risk_sort_key(r: dict) -> tuple:
    """组件风险排序键：超危 > 高危 > 中危 > 低危 > 未知 逐级降序，最后以 id 稳定排序。"""
    c = r["vuln_counts"]
    return (c.get("critical", 0), c.get("high", 0), c.get("medium", 0),
            c.get("low", 0), c.get("unknown", 0), r["id"])

_SCHEMA = """
CREATE TABLE IF NOT EXISTS config_mirror (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS whitelist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id   TEXT,
    artifact_id TEXT,
    name       TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS whitelist_version (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    whitelist_id  INTEGER NOT NULL,
    version       TEXT NOT NULL,
    source        TEXT NOT NULL,         -- 'pom' | 'gitlab' | 'gitlab-jar' | 'harbor' | 'docker'
    gitlab_project TEXT,
    pom_text      TEXT,
    source_ref    TEXT,                  -- 镜像 URL / GitLab 项目路径（展示用）
    scan_meta     TEXT,                  -- 奇安信二进制/镜像扫描参数 JSON（重扫用）
    summary_json  TEXT,
    report_md     TEXT,
    scan_status   TEXT NOT NULL DEFAULT 'pending',  -- pending|scanning|done|no_qianxin|failed
    error_msg     TEXT,
    scanned_at    TEXT,
    created_at    TEXT,
    UNIQUE(whitelist_id, version)
);

CREATE TABLE IF NOT EXISTS project (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id   TEXT,
    artifact_id TEXT,
    name       TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS project_version (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id    INTEGER NOT NULL,
    version       TEXT NOT NULL,
    source        TEXT NOT NULL,
    gitlab_project TEXT,
    pom_text      TEXT,
    source_ref    TEXT,                  -- 镜像 URL / GitLab 项目路径（展示用）
    scan_meta     TEXT,                  -- 奇安信二进制/镜像扫描参数 JSON（重扫用）
    summary_json  TEXT,
    report_md     TEXT,
    scan_status   TEXT NOT NULL DEFAULT 'pending',
    error_msg     TEXT,
    scanned_at    TEXT,
    created_at    TEXT,
    UNIQUE(project_id, version)
);

CREATE TABLE IF NOT EXISTS component (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id    TEXT,
    name        TEXT NOT NULL,
    version     TEXT,
    language    TEXT,
    coord       TEXT UNIQUE,             -- group:name:version
    license     TEXT,
    is_whitelist INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT
);

CREATE TABLE IF NOT EXISTS component_usage (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    component_id   INTEGER NOT NULL,
    ref_type       TEXT NOT NULL,        -- 'whitelist' | 'project'
    ref_id         INTEGER NOT NULL,     -- whitelist_version.id / project_version.id
    dependency_type TEXT NOT NULL,       -- 'direct' | 'transitive'
    created_at     TEXT,
    UNIQUE(component_id, ref_type, ref_id)
);

CREATE TABLE IF NOT EXISTS vulnerability (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    component_id     INTEGER NOT NULL,
    vuln_key         TEXT NOT NULL,
    vuln_id          TEXT,
    source           TEXT,
    title            TEXT,
    severity         TEXT,
    description      TEXT,
    fixed_version    TEXT,
    vulnerable_range TEXT,
    cwe              TEXT,
    cve              TEXT,
    solution         TEXT,
    references_json  TEXT,
    raw_json         TEXT,
    UNIQUE(component_id, vuln_key)
);

CREATE INDEX IF NOT EXISTS idx_usage_ref ON component_usage(ref_type, ref_id);
CREATE INDEX IF NOT EXISTS idx_vuln_comp ON vulnerability(component_id);
"""


def _now() -> str:
    now = datetime.now(_BEIJING_TZ)
    return now.strftime("%Y-%m-%d %H:%M:%S")


def _coord(group: Optional[str], name: str, version: Optional[str]) -> str:
    return f"{group or ''}:{name}:{version or '?'}"


class Db:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        parent = os.path.dirname(os.path.abspath(db_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(_SCHEMA)
        # 兼容存量库：补充新增列（CREATE TABLE IF NOT EXISTS 不会修改已存在的表）
        for table in ("whitelist_version", "project_version"):
            cols = [r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")]
            for col in ("source_ref", "scan_meta"):
                if col not in cols:
                    self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} TEXT")
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # ---- config mirror ----
    def get_config_mirror(self) -> dict:
        rows = self.conn.execute("SELECT key, value FROM config_mirror").fetchall()
        out: dict[str, Any] = {}
        for r in rows:
            try:
                out[r["key"]] = json.loads(r["value"])
            except (ValueError, TypeError):
                out[r["key"]] = r["value"]
        return out

    def set_config_mirror(self, data: dict) -> None:
        for k, v in data.items():
            self.conn.execute(
                "INSERT INTO config_mirror(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (k, json.dumps(v, ensure_ascii=False)),
            )
        self.conn.commit()

    # ---- whitelist ----
    def upsert_whitelist(self, group: Optional[str], artifact: str, name: str) -> int:
        row = self.conn.execute(
            "SELECT id FROM whitelist WHERE group_id IS ? AND artifact_id IS ?",
            (group, artifact),
        ).fetchone()
        if row:
            return int(row["id"])
        cur = self.conn.execute(
            "INSERT INTO whitelist(group_id, artifact_id, name, created_at) VALUES(?,?,?,?)",
            (group, artifact, name, _now()),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def list_whitelists(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM whitelist ORDER BY id DESC").fetchall()]

    def get_whitelist(self, wid: int) -> Optional[dict]:
        r = self.conn.execute("SELECT * FROM whitelist WHERE id=?", (wid,)).fetchone()
        return dict(r) if r else None

    def delete_whitelist(self, wid: int) -> None:
        self.conn.execute("DELETE FROM whitelist WHERE id=?", (wid,))
        self.conn.commit()

    def add_whitelist_version(self, whitelist_id: int, version: str, source: str,
                              gitlab_project: Optional[str], pom_text: str,
                              source_ref: Optional[str] = None,
                              scan_meta: Optional[str] = None) -> int:
        """插入白名单版本；若 (whitelist_id, version) 已存在则视为「重导入/重扫」：

        复用同一版本行，清空旧组件引用（避免陈旧数据残留），并重置扫描状态/报表。
        """
        existing = self.conn.execute(
            "SELECT id FROM whitelist_version WHERE whitelist_id=? AND version=?",
            (whitelist_id, version)).fetchone()
        if existing:
            vid = int(existing["id"])
            self._clear_version_usages("whitelist", vid)
            self.conn.execute(
                "UPDATE whitelist_version SET source=?, gitlab_project=?, pom_text=?, "
                "source_ref=?, scan_meta=?, scan_status='pending', error_msg=NULL, "
                "summary_json=NULL, report_md=NULL, created_at=? WHERE id=?",
                (source, gitlab_project, pom_text, source_ref, scan_meta, _now(), vid))
            self.conn.commit()
            return vid
        cur = self.conn.execute(
            "INSERT INTO whitelist_version"
            "(whitelist_id, version, source, gitlab_project, pom_text, source_ref, scan_meta, "
            "scan_status, created_at) "
            "VALUES(?,?,?,?,?,?,?, 'pending', ?)",
            (whitelist_id, version, source, gitlab_project, pom_text, source_ref,
             scan_meta, _now()),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def list_whitelist_versions(self, whitelist_id: int) -> list[dict]:
        return self.list_versions("whitelist", whitelist_id)

    # ---- project ----
    def upsert_project(self, group: Optional[str], artifact: str, name: str) -> int:
        row = self.conn.execute(
            "SELECT id FROM project WHERE group_id IS ? AND artifact_id IS ?",
            (group, artifact),
        ).fetchone()
        if row:
            # 已存在时同步更新手动填写的项目名称（若提供了非空名称）
            if name:
                self.conn.execute(
                    "UPDATE project SET name=? WHERE id=?", (name, int(row["id"])))
                self.conn.commit()
            return int(row["id"])
        cur = self.conn.execute(
            "INSERT INTO project(group_id, artifact_id, name, created_at) VALUES(?,?,?,?)",
            (group, artifact, name, _now()),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def list_projects(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM project ORDER BY id DESC").fetchall()]

    def get_project(self, pid: int) -> Optional[dict]:
        r = self.conn.execute("SELECT * FROM project WHERE id=?", (pid,)).fetchone()
        return dict(r) if r else None

    def delete_project(self, pid: int) -> None:
        self.conn.execute("DELETE FROM project WHERE id=?", (pid,))
        self.conn.commit()

    def add_project_version(self, project_id: int, version: str, source: str,
                            gitlab_project: Optional[str], pom_text: str,
                            source_ref: Optional[str] = None,
                            scan_meta: Optional[str] = None) -> int:
        """插入项目版本；若 (project_id, version) 已存在则视为「重导入/重扫」（同 add_whitelist_version）。"""
        existing = self.conn.execute(
            "SELECT id FROM project_version WHERE project_id=? AND version=?",
            (project_id, version)).fetchone()
        if existing:
            vid = int(existing["id"])
            self._clear_version_usages("project", vid)
            self.conn.execute(
                "UPDATE project_version SET source=?, gitlab_project=?, pom_text=?, "
                "source_ref=?, scan_meta=?, scan_status='pending', error_msg=NULL, "
                "summary_json=NULL, report_md=NULL, created_at=? WHERE id=?",
                (source, gitlab_project, pom_text, source_ref, scan_meta, _now(), vid))
            self.conn.commit()
            return vid
        cur = self.conn.execute(
            "INSERT INTO project_version"
            "(project_id, version, source, gitlab_project, pom_text, source_ref, scan_meta, "
            "scan_status, created_at) "
            "VALUES(?,?,?,?,?,?,?, 'pending', ?)",
            (project_id, version, source, gitlab_project, pom_text, source_ref,
             scan_meta, _now()),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def _clear_version_usages(self, ref_type: str, vid: int) -> None:
        """删除某版本的全部组件引用，并级联清理不再被任何版本引用的组件及其漏洞。

        仅清理 usage 与孤儿组件，保留版本行与所属 owner（用于重扫前的重置）。
        """
        comp_rows = self.conn.execute(
            "SELECT component_id FROM component_usage WHERE ref_type=? AND ref_id=?",
            (ref_type, vid)).fetchall()
        self.conn.execute(
            "DELETE FROM component_usage WHERE ref_type=? AND ref_id=?", (ref_type, vid))
        for r in comp_rows:
            cid = int(r["component_id"])
            remaining = self.conn.execute(
                "SELECT 1 FROM component_usage WHERE component_id=?", (cid,)).fetchone()
            if not remaining:
                self.conn.execute("DELETE FROM vulnerability WHERE component_id=?", (cid,))
                self.conn.execute("DELETE FROM component WHERE id=?", (cid,))

    def list_project_versions(self, project_id: int) -> list[dict]:
        return self.list_versions("project", project_id)

    # generic version accessors (whitelist_version / project_version share shape)
    def get_version(self, ref_type: str, vid: int) -> Optional[dict]:
        table = "whitelist_version" if ref_type == "whitelist" else "project_version"
        r = self.conn.execute(f"SELECT * FROM {table} WHERE id=?", (vid,)).fetchone()
        return dict(r) if r else None

    def list_versions(self, ref_type: str, owner_id: int) -> list[dict]:
        table = "whitelist_version" if ref_type == "whitelist" else "project_version"
        id_col = "whitelist_id" if ref_type == "whitelist" else "project_id"
        rows = [dict(r) for r in self.conn.execute(
            f"SELECT * FROM {table} WHERE {id_col}=? ORDER BY id DESC", (owner_id,)).fetchall()]
        for r in rows:
            r["stats"] = self.version_stats(ref_type, r["id"])
        return rows

    def version_stats(self, ref_type: str, vid: int) -> dict:
        """Aggregate component + severity breakdown for one version.

        Counts vulnerabilities linked to the components referenced by the
        version (via ``component_usage``), grouped by normalized severity.
        """
        comp = self.conn.execute(
            "SELECT COUNT(*) AS c, "
            "SUM(CASE WHEN dependency_type='direct' THEN 1 ELSE 0 END) AS d, "
            "SUM(CASE WHEN dependency_type='transitive' THEN 1 ELSE 0 END) AS t "
            "FROM component_usage WHERE ref_type=? AND ref_id=?",
            (ref_type, vid)).fetchone()
        sev_rows = self.conn.execute(
            "SELECT v.severity, COUNT(*) AS cnt FROM vulnerability v "
            "JOIN component_usage u ON u.component_id=v.component_id "
            "WHERE u.ref_type=? AND u.ref_id=? GROUP BY v.severity",
            (ref_type, vid)).fetchall()
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        for r in sev_rows:
            s = (r["severity"] or "unknown").lower()
            if s in counts:
                counts[s] = int(r["cnt"])
            else:
                counts["unknown"] += int(r["cnt"])
        return {
            "component_count": int(comp["c"] or 0),
            "direct_count": int(comp["d"] or 0),
            "transitive_count": int(comp["t"] or 0),
            "vuln_counts": counts,
            "vuln_total": sum(counts.values()),
        }

    def delete_version(self, ref_type: str, vid: int) -> None:
        table = "whitelist_version" if ref_type == "whitelist" else "project_version"
        owner_col = "whitelist_id" if ref_type == "whitelist" else "project_id"
        owner_table = "whitelist" if ref_type == "whitelist" else "project"
        # 记录所属的白名单项/项目，用于最后一个版本删除后的级联清理
        owner_row = self.conn.execute(
            f"SELECT {owner_col} AS owner_id FROM {table} WHERE id=?", (vid,)).fetchone()
        self._clear_version_usages(ref_type, vid)
        self.conn.execute(f"DELETE FROM {table} WHERE id=?", (vid,))

        # 级联删除 owner：最后一个版本被删后，白名单项/项目项一并删除，
        # 下次导入同坐标时由 upsert_whitelist / upsert_project 自动重建。
        if owner_row is not None:
            owner_id = int(owner_row["owner_id"])
            remaining = self.conn.execute(
                f"SELECT 1 FROM {table} WHERE {owner_col}=? LIMIT 1", (owner_id,)).fetchone()
            if not remaining:
                self.conn.execute(f"DELETE FROM {owner_table} WHERE id=?", (owner_id,))
                if ref_type == "whitelist":
                    # 清除不再被任何白名单版本引用的组件的白名单标记
                    self.conn.execute(
                        "UPDATE component SET is_whitelist=0 WHERE is_whitelist=1 "
                        "AND id NOT IN (SELECT cu.component_id FROM component_usage cu "
                        "JOIN whitelist_version wv ON cu.ref_id=wv.id "
                        "WHERE cu.ref_type='whitelist')")
        self.conn.commit()

    def set_version_status(self, ref_type: str, vid: int, status: str,
                           error: Optional[str] = None) -> None:
        table = "whitelist_version" if ref_type == "whitelist" else "project_version"
        if status in ("done", "no_qianxin", "failed"):
            self.conn.execute(
                f"UPDATE {table} SET scan_status=?, error_msg=?, scanned_at=? WHERE id=?",
                (status, error, _now(), vid))
        else:
            self.conn.execute(
                f"UPDATE {table} SET scan_status=?, error_msg=? WHERE id=?",
                (status, error, vid))
        self.conn.commit()

    def set_version_report(self, ref_type: str, vid: int, summary: dict, report_md: str) -> None:
        table = "whitelist_version" if ref_type == "whitelist" else "project_version"
        self.conn.execute(
            f"UPDATE {table} SET summary_json=?, report_md=? WHERE id=?",
            (json.dumps(summary, ensure_ascii=False), report_md, vid))
        self.conn.commit()

    # ---- component catalogue ----
    def upsert_component(self, group: Optional[str], name: str, version: Optional[str],
                         language: str, license: Optional[str],
                         is_whitelist: bool) -> int:
        c = _coord(group, name, version)
        row = self.conn.execute("SELECT id, is_whitelist, license FROM component WHERE coord=?",
                                (c,)).fetchone()
        if row:
            cid = int(row["id"])
            # merge: keep whitelist flag if either says True; refresh license when missing
            new_flag = 1 if (row["is_whitelist"] or is_whitelist) else 0
            if license and not row["license"]:
                self.conn.execute(
                    "UPDATE component SET is_whitelist=?, license=? WHERE id=?",
                    (new_flag, license, cid))
            elif new_flag != row["is_whitelist"]:
                self.conn.execute(
                    "UPDATE component SET is_whitelist=? WHERE id=?", (new_flag, cid))
            self.conn.commit()
            return cid
        cur = self.conn.execute(
            "INSERT INTO component(group_id, name, version, language, coord, license, "
            "is_whitelist, created_at) VALUES(?,?,?,?,?,?,?,?)",
            (group, name, version, language, c, license, 1 if is_whitelist else 0, _now()))
        self.conn.commit()
        return int(cur.lastrowid)

    def get_component(self, coord: str) -> Optional[dict]:
        r = self.conn.execute("SELECT * FROM component WHERE coord=?", (coord,)).fetchone()
        return dict(r) if r else None

    def add_usage(self, component_id: int, ref_type: str, ref_id: int,
                  dependency_type: str) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO component_usage"
            "(component_id, ref_type, ref_id, dependency_type, created_at) VALUES(?,?,?,?,?)",
            (component_id, ref_type, ref_id, dependency_type, _now()))
        self.conn.commit()

    def add_vulnerability(self, component_id: int, vuln: dict) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO vulnerability"
            "(component_id, vuln_key, vuln_id, source, title, severity, description, "
            "fixed_version, vulnerable_range, cwe, cve, solution, references_json, raw_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (component_id, vuln["vuln_key"], vuln.get("vuln_id"), vuln.get("source"),
             vuln.get("title"), vuln.get("severity"), vuln.get("description"),
             vuln.get("fixed_version"), vuln.get("vulnerable_range"), vuln.get("cwe"),
             vuln.get("cve"), vuln.get("solution"),
             json.dumps(vuln.get("references") or [], ensure_ascii=False),
             json.dumps(vuln.get("raw") or {}, ensure_ascii=False)))
        self.conn.commit()

    def list_components(self, filters: Optional[dict] = None) -> list[dict]:
        """Return components with aggregate counts (usage + vulns)."""
        filters = filters or {}
        where = []
        params: list[Any] = []
        if filters.get("q"):
            like = f"%{filters['q']}%"
            where.append("(name LIKE ? OR group_id LIKE ? OR coord LIKE ?)")
            params.extend([like, like, like])
        if filters.get("is_whitelist") is not None:
            where.append("is_whitelist = ?")
            params.append(1 if filters["is_whitelist"] else 0)
        if filters.get("severity"):
            # components having at least one vuln of this severity
            where.append(
                "id IN (SELECT component_id FROM vulnerability WHERE severity = ?)")
            params.append(filters["severity"])
        sql = ("SELECT c.*, "
               "(SELECT COUNT(*) FROM component_usage u WHERE u.component_id=c.id) AS usage_count, "
               "(SELECT COUNT(*) FROM vulnerability v WHERE v.component_id=c.id) AS vuln_count "
               "FROM component c")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY c.id DESC"
        rows = [dict(r) for r in self.conn.execute(sql, params).fetchall()]
        # 按严重程度分组统计，供列表按「类型:数量」分色展示（与 list_version_components 一致）
        sev_rows = self.conn.execute(
            "SELECT component_id, severity, COUNT(*) AS cnt "
            "FROM vulnerability GROUP BY component_id, severity").fetchall()
        per: dict[int, dict[str, int]] = {}
        for r in sev_rows:
            s = (r["severity"] or "unknown").lower()
            if s not in _SEV_KEYS:
                s = "unknown"
            per.setdefault(int(r["component_id"]), {})[s] = int(r["cnt"])
        for r in rows:
            counts = per.get(int(r["id"]), {})
            r["vuln_counts"] = {k: counts.get(k, 0) for k in _SEV_KEYS}
        rows.sort(key=_risk_sort_key, reverse=True)
        return rows

    def get_component_detail(self, coord: str) -> Optional[dict]:
        comp = self.get_component(coord)
        if not comp:
            return None
        cid = comp["id"]
        vulns = [dict(r) for r in self.conn.execute(
            "SELECT * FROM vulnerability WHERE component_id=? "
            "ORDER BY CASE COALESCE(lower(severity), 'unknown') "
            "  WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "  WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id",
            (cid,)).fetchall()]
        # whitelist versions that reference this component
        wlv = self.conn.execute(
            "SELECT wv.id, wv.version, w.name, w.group_id, w.artifact_id, u.dependency_type "
            "FROM component_usage u "
            "JOIN whitelist_version wv ON wv.id=u.ref_id "
            "JOIN whitelist w ON w.id=wv.whitelist_id "
            "WHERE u.ref_type='whitelist' AND u.component_id=?", (cid,)).fetchall()
        # project versions that reference this component
        pjv = self.conn.execute(
            "SELECT pv.id, pv.version, p.name, p.group_id, p.artifact_id, u.dependency_type "
            "FROM component_usage u "
            "JOIN project_version pv ON pv.id=u.ref_id "
            "JOIN project p ON p.id=pv.project_id "
            "WHERE u.ref_type='project' AND u.component_id=?", (cid,)).fetchall()
        comp["vulnerabilities"] = vulns
        comp["whitelist_versions"] = [dict(r) for r in wlv]
        comp["project_versions"] = [dict(r) for r in pjv]
        return comp

    def projects_for_component(self, coord: str) -> list[str]:
        """返回引用该坐标组件的全部业务项目（「项目管理」维度），去重后以「项目名称:版本」列出。

        用于白名单报告中「影响项目」列与中危及以上漏洞影响产品汇总小节。
        若该坐标组件未被任何项目引用，返回空列表。

        注意：同一坐标在库中可能存在多行（如 whitelist 行与 project 行），
        因此按 ``coord`` 关联全部 ``component`` 行，而不是取单一 component id，
        避免取到 whitelist 行后漏掉 project 维度的引用。
        """
        rows = self.conn.execute(
            "SELECT DISTINCT p.name, pv.version "
            "FROM component c "
            "JOIN component_usage u ON u.component_id=c.id "
            "JOIN project_version pv ON pv.id=u.ref_id "
            "JOIN project p ON p.id=pv.project_id "
            "WHERE u.ref_type='project' AND c.coord=?", (coord,)).fetchall()
        out = []
        seen = set()
        for r in rows:
            name = (r["name"] or "").strip() or f"project:{r['version']}"
            ver = (r["version"] or "").strip() or "—"
            label = f"{name}:{ver}"
            if label not in seen:
                seen.add(label)
                out.append(label)
        # 稳定排序：先按项目名称，再按版本
        return sorted(out)

    def vulnerabilities_for_component(self, cid: int) -> list[dict]:
        """一个组件的全部漏洞行（供报表从库中重建漏洞明细）。"""
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM vulnerability WHERE component_id=? ORDER BY id", (cid,)).fetchall()]

    def components_for_version(self, ref_type: str, vid: int) -> list[dict]:
        rows = self.conn.execute(
            "SELECT c.*, u.dependency_type, "
            "(SELECT COUNT(*) FROM vulnerability v WHERE v.component_id=c.id) AS vuln_count "
            "FROM component_usage u JOIN component c ON c.id=u.component_id "
            "WHERE u.ref_type=? AND u.ref_id=?", (ref_type, vid)).fetchall()
        return [dict(r) for r in rows]

    def list_version_components(self, ref_type: str, vid: int) -> list[dict]:
        """Components referenced by a version, shaped like the catalogue list.

        Mirrors :meth:`list_components` columns (incl. ``usage_count`` /
        ``vuln_count``) plus the ``dependency_type`` for this version and a
        per-severity breakdown ``vuln_counts``.
        """
        rows = [dict(r) for r in self.conn.execute(
            "SELECT c.*, u.dependency_type, "
            "(SELECT COUNT(*) FROM vulnerability v WHERE v.component_id=c.id) AS vuln_count, "
            "(SELECT COUNT(*) FROM component_usage u2 WHERE u2.component_id=c.id) AS usage_count "
            "FROM component_usage u JOIN component c ON c.id=u.component_id "
            "WHERE u.ref_type=? AND u.ref_id=? ORDER BY c.id DESC", (ref_type, vid)).fetchall()]
        sev_rows = self.conn.execute(
            "SELECT v.component_id, v.severity, COUNT(*) AS cnt "
            "FROM vulnerability v JOIN component_usage u ON u.component_id=v.component_id "
            "WHERE u.ref_type=? AND u.ref_id=? GROUP BY v.component_id, v.severity",
            (ref_type, vid)).fetchall()
        per = {}
        for r in sev_rows:
            s = (r["severity"] or "unknown").lower()
            if s not in _SEV_KEYS:
                s = "unknown"
            per.setdefault(int(r["component_id"]), {})[s] = int(r["cnt"])
        for r in rows:
            counts = per.get(int(r["id"]), {})
            r["vuln_counts"] = {k: counts.get(k, 0) for k in _SEV_KEYS}
        rows.sort(key=_risk_sort_key, reverse=True)
        return rows
