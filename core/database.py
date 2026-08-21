import json
import sqlite3
import aiosqlite
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from core.config import settings
from core.logger import logger

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS attack_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    service TEXT NOT NULL,
    event_type TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    username TEXT,
    password TEXT,
    http_method TEXT,
    http_path TEXT,
    http_headers TEXT,
    payload TEXT,
    country TEXT,
    country_code TEXT,
    city TEXT,
    lat REAL,
    lon REAL,
    org TEXT,
    asn TEXT,
    ioc_tags TEXT,
    risk_score INTEGER DEFAULT 0,
    severity TEXT DEFAULT 'LOW',
    mitre_technique TEXT,
    session_id TEXT
);

CREATE TABLE IF NOT EXISTS ioc_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type TEXT NOT NULL,
    ioc_value TEXT UNIQUE NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    hit_count INTEGER DEFAULT 1,
    threat_level TEXT DEFAULT 'MEDIUM',
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON attack_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON attack_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_service ON attack_events(service);
CREATE INDEX IF NOT EXISTS idx_events_severity ON attack_events(severity);
CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc_records(ioc_value);
"""

class DatabaseManager:
    def __init__(self, db_path: str = settings.DB_PATH):
        self.db_path = db_path
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init_sync_db()

    def init_sync_db(self):
        """Initialize the database schema synchronously at startup."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(SCHEMA_SQL)
            conn.commit()

    async def get_connection(self) -> aiosqlite.Connection:
        conn = await aiosqlite.connect(self.db_path)
        conn.row_factory = aiosqlite.Row
        return conn

    def insert_event_sync(self, event: Dict[str, Any]) -> int:
        """Synchronous insert for thread-based honeypot services (e.g. Paramiko SSH)."""
        sql = """
        INSERT INTO attack_events (
            timestamp, service, event_type, src_ip, src_port, username, password,
            http_method, http_path, http_headers, payload, country, country_code,
            city, lat, lon, org, asn, ioc_tags, risk_score, severity, mitre_technique, session_id
        ) VALUES (
            :timestamp, :service, :event_type, :src_ip, :src_port, :username, :password,
            :http_method, :http_path, :http_headers, :payload, :country, :country_code,
            :city, :lat, :lon, :org, :asn, :ioc_tags, :risk_score, :severity, :mitre_technique, :session_id
        )
        """
        data = {
            "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "service": event.get("service", "UNKNOWN"),
            "event_type": event.get("event_type", "GENERIC_EVENT"),
            "src_ip": event.get("src_ip", "0.0.0.0"),
            "src_port": event.get("src_port", 0),
            "username": event.get("username", None),
            "password": event.get("password", None),
            "http_method": event.get("http_method", None),
            "http_path": event.get("http_path", None),
            "http_headers": json.dumps(event.get("http_headers", {})) if isinstance(event.get("http_headers"), dict) else event.get("http_headers"),
            "payload": event.get("payload", None),
            "country": event.get("country", "Unknown"),
            "country_code": event.get("country_code", "XX"),
            "city": event.get("city", "Unknown"),
            "lat": event.get("lat", 0.0),
            "lon": event.get("lon", 0.0),
            "org": event.get("org", "Unknown ISP"),
            "asn": event.get("asn", "Unknown"),
            "ioc_tags": json.dumps(event.get("ioc_tags", [])) if isinstance(event.get("ioc_tags"), list) else event.get("ioc_tags", "[]"),
            "risk_score": event.get("risk_score", 10),
            "severity": event.get("severity", "LOW"),
            "mitre_technique": event.get("mitre_technique", None),
            "session_id": event.get("session_id", None)
        }
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(sql, data)
            event_id = cursor.lastrowid
            
            # Update IoC record for IP
            self._update_ioc_sync(cursor, "IP_ADDRESS", data["src_ip"], data["severity"], f"Attacked {data['service']}")
            if data["password"]:
                self._update_ioc_sync(cursor, "PASSWORD_ATTEMPT", data["password"], "LOW", f"Username: {data['username']}")
            if data["payload"]:
                # Store sample payload IoC
                truncated_payload = (data["payload"][:100] + '...') if len(data["payload"]) > 100 else data["payload"]
                self._update_ioc_sync(cursor, "PAYLOAD_SIGNATURE", truncated_payload, data["severity"], f"Vector: {data['mitre_technique']}")

            conn.commit()
            return event_id

    def _update_ioc_sync(self, cursor: sqlite3.Cursor, ioc_type: str, ioc_value: str, threat_level: str, notes: str):
        if not ioc_value or len(ioc_value.strip()) == 0:
            return
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute("""
            INSERT INTO ioc_records (ioc_type, ioc_value, first_seen, last_seen, hit_count, threat_level, notes)
            VALUES (?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(ioc_value) DO UPDATE SET
                last_seen = excluded.last_seen,
                hit_count = ioc_records.hit_count + 1,
                threat_level = CASE 
                    WHEN excluded.threat_level = 'CRITICAL' THEN 'CRITICAL'
                    WHEN excluded.threat_level = 'HIGH' AND ioc_records.threat_level != 'CRITICAL' THEN 'HIGH'
                    ELSE ioc_records.threat_level
                END
        """, (ioc_type, ioc_value, now, now, threat_level, notes))

    async def insert_event_async(self, event: Dict[str, Any]) -> int:
        return self.insert_event_sync(event)

    async def get_recent_events(self, limit: int = 50, offset: int = 0, service: Optional[str] = None, severity: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT * FROM attack_events WHERE 1=1"
        params = []
        
        if service and service.upper() != "ALL":
            query += " AND service = ?"
            params.append(service.upper())
        if severity and severity.upper() != "ALL":
            query += " AND severity = ?"
            params.append(severity.upper())
        if search:
            query += " AND (src_ip LIKE ? OR username LIKE ? OR http_path LIKE ? OR payload LIKE ? OR country LIKE ?)"
            s_param = f"%{search}%"
            params.extend([s_param, s_param, s_param, s_param, s_param])
            
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute(query, params)
            rows = await cursor.fetchall()
            results = []
            for row in rows:
                item = dict(row)
                try:
                    item["ioc_tags"] = json.loads(item["ioc_tags"]) if item["ioc_tags"] else []
                except Exception:
                    item["ioc_tags"] = [item["ioc_tags"]] if item["ioc_tags"] else []
                try:
                    item["http_headers"] = json.loads(item["http_headers"]) if item["http_headers"] else {}
                except Exception:
                    pass
                results.append(item)
            return results

    async def get_stats(self) -> Dict[str, Any]:
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            
            # Total events & unique IPs
            cursor = await conn.execute("SELECT COUNT(*) as total_events, COUNT(DISTINCT src_ip) as unique_attackers FROM attack_events")
            general = dict(await cursor.fetchone())
            
            # High/Critical risk events
            cursor = await conn.execute("SELECT COUNT(*) as high_risk_count FROM attack_events WHERE severity IN ('HIGH', 'CRITICAL')")
            high_risk = dict(await cursor.fetchone())
            
            # Events by service
            cursor = await conn.execute("SELECT service, COUNT(*) as count FROM attack_events GROUP BY service")
            by_service = [dict(r) for r in await cursor.fetchall()]
            
            # Events by severity
            cursor = await conn.execute("SELECT severity, COUNT(*) as count FROM attack_events GROUP BY severity")
            by_severity = [dict(r) for r in await cursor.fetchall()]

            # Top countries
            cursor = await conn.execute("SELECT country, country_code, COUNT(*) as count FROM attack_events WHERE country IS NOT NULL AND country != 'Unknown' GROUP BY country, country_code ORDER BY count DESC LIMIT 8")
            top_countries = [dict(r) for r in await cursor.fetchall()]

            # Top passwords
            cursor = await conn.execute("SELECT password, COUNT(*) as count FROM attack_events WHERE password IS NOT NULL AND password != '' GROUP BY password ORDER BY count DESC LIMIT 8")
            top_passwords = [dict(r) for r in await cursor.fetchall()]

            # Top usernames
            cursor = await conn.execute("SELECT username, COUNT(*) as count FROM attack_events WHERE username IS NOT NULL AND username != '' GROUP BY username ORDER BY count DESC LIMIT 8")
            top_usernames = [dict(r) for r in await cursor.fetchall()]

            # Top HTTP Paths / Payloads
            cursor = await conn.execute("SELECT http_path, COUNT(*) as count FROM attack_events WHERE http_path IS NOT NULL AND http_path != '' GROUP BY http_path ORDER BY count DESC LIMIT 8")
            top_paths = [dict(r) for r in await cursor.fetchall()]

            # Top MITRE Techniques
            cursor = await conn.execute("SELECT mitre_technique, COUNT(*) as count FROM attack_events WHERE mitre_technique IS NOT NULL GROUP BY mitre_technique ORDER BY count DESC LIMIT 6")
            top_mitre = [dict(r) for r in await cursor.fetchall()]

            return {
                "total_events": general["total_events"],
                "unique_attackers": general["unique_attackers"],
                "high_risk_count": high_risk["high_risk_count"],
                "by_service": by_service,
                "by_severity": by_severity,
                "top_countries": top_countries,
                "top_passwords": top_passwords,
                "top_usernames": top_usernames,
                "top_paths": top_paths,
                "top_mitre": top_mitre
            }

    async def get_all_iocs(self) -> List[Dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("SELECT * FROM ioc_records ORDER BY hit_count DESC")
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

db = DatabaseManager()
