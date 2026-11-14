"""
Database Module - SQLite storage for scan history, alerts, and whitelist.

Every scan and every whitelist entry belongs to a client (client_id). When the
app runs on a user's own computer there is a single client, 'local'. When it
is hosted for many visitors, each browser gets its own client_id, so visitors
never see each other's scans and cannot trust a network on someone else's
behalf (which would let an attacker "whitelist" their own Evil Twin).
"""

import sqlite3
import json
import os
from datetime import datetime

LOCAL = 'local'


class Database:
    """Manages SQLite database for the Evil Twin Detector."""

    def __init__(self, db_path=None):
        # Path can be overridden with the DATABASE_PATH environment variable
        # (see config.py), which also lets tests use an isolated database.
        self.db_path = db_path or os.environ.get('DATABASE_PATH', 'evil_twin_detector.db')
        # Create the schema on construction. Previously this only happened in
        # app.py's __main__ block, so starting the app any other way
        # (flask run, gunicorn, a WSGI host) failed with
        # "sqlite3.OperationalError: no such table: scans".
        # CREATE TABLE IF NOT EXISTS makes this safe to run every time.
        self.initialize()

    def _connect(self):
        """Create a database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    _TABLE_INFO = {'scans': 'PRAGMA table_info(scans)', 'whitelist': 'PRAGMA table_info(whitelist)'}

    @classmethod
    def _columns(cls, cursor, table):
        return {row[1] for row in cursor.execute(cls._TABLE_INFO[table])}

    def initialize(self):
        """Create database tables if they don't exist, and upgrade older databases."""
        conn = self._connect()
        cursor = conn.cursor()

        cursor.executescript('''
            -- Scan sessions
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                total_networks INTEGER DEFAULT 0,
                high_risk_count INTEGER DEFAULT 0,
                medium_risk_count INTEGER DEFAULT 0,
                low_risk_count INTEGER DEFAULT 0,
                threat_level TEXT DEFAULT 'safe',
                client_id TEXT NOT NULL DEFAULT 'local'
            );

            -- Individual network observations
            CREATE TABLE IF NOT EXISTS networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                ssid TEXT,
                bssid TEXT NOT NULL,
                signal_strength INTEGER,
                channel INTEGER,
                frequency TEXT,
                encryption TEXT,
                risk_score INTEGER DEFAULT 0,
                risk_level TEXT DEFAULT 'low',
                risk_factors TEXT,  -- JSON
                vendor TEXT,
                timestamp TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            );

            -- Alerts log
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                ssid TEXT,
                bssid TEXT,
                risk_level TEXT,
                risk_score INTEGER,
                message TEXT,
                timestamp TEXT,
                acknowledged INTEGER DEFAULT 0,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            );

            -- Trusted networks whitelist (one list per client)
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT NOT NULL DEFAULT 'local',
                bssid TEXT NOT NULL,
                ssid TEXT,
                added_date TEXT,
                notes TEXT,
                UNIQUE (client_id, bssid)
            );
        ''')

        # Upgrade databases created before clients existed
        if 'client_id' not in self._columns(cursor, 'scans'):
            cursor.execute("ALTER TABLE scans ADD COLUMN client_id TEXT NOT NULL DEFAULT 'local'")
        if 'client_id' not in self._columns(cursor, 'whitelist'):
            # The old table had UNIQUE(bssid); SQLite cannot drop a constraint, so rebuild it.
            cursor.executescript('''
                CREATE TABLE whitelist_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT NOT NULL DEFAULT 'local',
                    bssid TEXT NOT NULL,
                    ssid TEXT,
                    added_date TEXT,
                    notes TEXT,
                    UNIQUE (client_id, bssid)
                );
                INSERT INTO whitelist_new (id, client_id, bssid, ssid, added_date, notes)
                    SELECT id, 'local', bssid, ssid, added_date, notes FROM whitelist;
                DROP TABLE whitelist;
                ALTER TABLE whitelist_new RENAME TO whitelist;
            ''')

        cursor.executescript('''
            -- Indexes for performance
            CREATE INDEX IF NOT EXISTS idx_networks_scan_id ON networks(scan_id);
            CREATE INDEX IF NOT EXISTS idx_networks_bssid ON networks(bssid);
            CREATE INDEX IF NOT EXISTS idx_networks_ssid ON networks(ssid);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
            CREATE INDEX IF NOT EXISTS idx_scans_client ON scans(client_id);
        ''')

        conn.commit()
        conn.close()
        print("[Database] Initialized successfully")

    def save_scan(self, analyzed_networks, client_id=LOCAL):
        """Save a complete scan session with all detected networks."""
        conn = self._connect()
        cursor = conn.cursor()
        timestamp = datetime.now().isoformat()

        # Count risk levels
        high = sum(1 for n in analyzed_networks if n.get('risk_level') == 'high')
        medium = sum(1 for n in analyzed_networks if n.get('risk_level') == 'medium')
        low = sum(1 for n in analyzed_networks if n.get('risk_level') == 'low')

        threat = 'critical' if high > 0 else ('warning' if medium > 0 else 'safe')

        # Insert scan session
        cursor.execute('''
            INSERT INTO scans (timestamp, total_networks, high_risk_count,
                             medium_risk_count, low_risk_count, threat_level, client_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, len(analyzed_networks), high, medium, low, threat, client_id))

        scan_id = cursor.lastrowid

        # Insert each network
        for network in analyzed_networks:
            cursor.execute('''
                INSERT INTO networks (scan_id, ssid, bssid, signal_strength, channel,
                                    frequency, encryption, risk_score, risk_level,
                                    risk_factors, vendor, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                network.get('ssid', ''),
                network.get('bssid', ''),
                network.get('signal_strength', -100),
                network.get('channel', 0),
                network.get('frequency', ''),
                network.get('encryption', ''),
                network.get('risk_score', 0),
                network.get('risk_level', 'low'),
                json.dumps(network.get('risk_factors', [])),
                network.get('vendor', ''),
                network.get('timestamp', timestamp)
            ))

            # Create alert for medium and high risk networks
            if network.get('risk_level') in ('medium', 'high'):
                factors = network.get('risk_factors', [])
                message = '; '.join(
                    f.get('detail', f.get('factor', '')) if isinstance(f, dict) else str(f)
                    for f in factors[:3]
                )
                cursor.execute('''
                    INSERT INTO alerts (scan_id, ssid, bssid, risk_level,
                                      risk_score, message, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    scan_id,
                    network.get('ssid', ''),
                    network.get('bssid', ''),
                    network.get('risk_level', ''),
                    network.get('risk_score', 0),
                    message,
                    timestamp
                ))

        conn.commit()
        conn.close()
        return scan_id

    def get_statistics(self, client_id=LOCAL):
        """Get statistics for one client."""
        conn = self._connect()
        cursor = conn.cursor()

        stats = {}

        cursor.execute('SELECT COUNT(*) as count FROM scans WHERE client_id = ?', (client_id,))
        stats['total_scans'] = cursor.fetchone()['count']

        cursor.execute('''
            SELECT COUNT(DISTINCT n.bssid) as count FROM networks n
            JOIN scans s ON s.id = n.scan_id WHERE s.client_id = ?
        ''', (client_id,))
        stats['unique_networks'] = cursor.fetchone()['count']

        cursor.execute('''
            SELECT COUNT(*) as count FROM alerts a
            JOIN scans s ON s.id = a.scan_id WHERE s.client_id = ?
        ''', (client_id,))
        stats['total_alerts'] = cursor.fetchone()['count']

        cursor.execute('''
            SELECT COUNT(*) as count FROM alerts a
            JOIN scans s ON s.id = a.scan_id WHERE s.client_id = ? AND a.risk_level = 'high'
        ''', (client_id,))
        stats['high_risk_detections'] = cursor.fetchone()['count']

        cursor.execute('SELECT timestamp FROM scans WHERE client_id = ? ORDER BY id DESC LIMIT 1',
                       (client_id,))
        row = cursor.fetchone()
        stats['last_scan'] = row['timestamp'] if row else None

        cursor.execute('''
            SELECT n.risk_level, COUNT(*) as count FROM networks n
            JOIN scans s ON s.id = n.scan_id WHERE s.client_id = ?
            GROUP BY n.risk_level
        ''', (client_id,))
        stats['risk_distribution'] = {row['risk_level']: row['count'] for row in cursor.fetchall()}

        conn.close()
        return stats

    def get_recent_alerts(self, limit=10, client_id=LOCAL):
        """Get a client's most recent alerts."""
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT a.* FROM alerts a JOIN scans s ON s.id = a.scan_id
            WHERE s.client_id = ?
            ORDER BY a.timestamp DESC
            LIMIT ?
        ''', (client_id, limit))

        alerts = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return alerts

    def get_scan_history(self, limit=50, client_id=LOCAL):
        """Get a client's scan session history."""
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM scans WHERE client_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (client_id, limit))

        scans = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return scans

    def get_network_details(self, bssid, client_id=LOCAL):
        """Get the latest observation of a network in one client's scans."""
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT n.* FROM networks n JOIN scans s ON s.id = n.scan_id
            WHERE n.bssid = ? AND s.client_id = ?
            ORDER BY n.timestamp DESC
            LIMIT 1
        ''', (bssid, client_id))

        row = cursor.fetchone()
        if row:
            network = dict(row)
            network['risk_factors'] = json.loads(network.get('risk_factors', '[]'))
            conn.close()
            return network

        conn.close()
        return None

    def get_network_history(self, bssid, client_id=LOCAL):
        """Get one client's historical observations of a network."""
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT n.signal_strength, n.encryption, n.channel, n.risk_score, n.timestamp
            FROM networks n JOIN scans s ON s.id = n.scan_id
            WHERE n.bssid = ? AND s.client_id = ?
            ORDER BY n.timestamp DESC
            LIMIT 100
        ''', (bssid, client_id))

        history = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return history

    def get_whitelist(self, client_id=LOCAL):
        """Get a client's whitelisted networks."""
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM whitelist WHERE client_id = ? ORDER BY added_date DESC',
                       (client_id,))
        whitelist = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return whitelist

    def add_to_whitelist(self, bssid, ssid='', notes='', client_id=LOCAL):
        """Add a network to a client's trusted whitelist."""
        conn = self._connect()
        cursor = conn.cursor()

        try:
            cursor.execute('''
                INSERT OR REPLACE INTO whitelist (client_id, bssid, ssid, added_date, notes)
                VALUES (?, ?, ?, ?, ?)
            ''', (client_id, bssid, ssid, datetime.now().isoformat(), notes))
            conn.commit()
        except sqlite3.IntegrityError:
            pass

        conn.close()

    def remove_from_whitelist(self, bssid, client_id=LOCAL):
        """Remove a network from a client's whitelist."""
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM whitelist WHERE bssid = ? AND client_id = ?', (bssid, client_id))
        conn.commit()
        conn.close()
