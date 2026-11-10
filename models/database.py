"""
Database Module - SQLite storage for scan history, alerts, and whitelist.
"""

import sqlite3
import json
import os
from datetime import datetime


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

    def initialize(self):
        """Create database tables if they don't exist."""
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
                threat_level TEXT DEFAULT 'safe'
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

            -- Trusted networks whitelist
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT UNIQUE NOT NULL,
                ssid TEXT,
                added_date TEXT,
                notes TEXT
            );

            -- Indexes for performance
            CREATE INDEX IF NOT EXISTS idx_networks_scan_id ON networks(scan_id);
            CREATE INDEX IF NOT EXISTS idx_networks_bssid ON networks(bssid);
            CREATE INDEX IF NOT EXISTS idx_networks_ssid ON networks(ssid);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
        ''')

        conn.commit()
        conn.close()
        print("[Database] Initialized successfully")

    def save_scan(self, analyzed_networks):
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
                             medium_risk_count, low_risk_count, threat_level)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (timestamp, len(analyzed_networks), high, medium, low, threat))

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

    def get_statistics(self):
        """Get overall system statistics."""
        conn = self._connect()
        cursor = conn.cursor()

        stats = {}

        # Total scans
        cursor.execute('SELECT COUNT(*) as count FROM scans')
        stats['total_scans'] = cursor.fetchone()['count']

        # Total unique networks seen
        cursor.execute('SELECT COUNT(DISTINCT bssid) as count FROM networks')
        stats['unique_networks'] = cursor.fetchone()['count']

        # Total alerts
        cursor.execute('SELECT COUNT(*) as count FROM alerts')
        stats['total_alerts'] = cursor.fetchone()['count']

        # High risk detections
        cursor.execute("SELECT COUNT(*) as count FROM alerts WHERE risk_level='high'")
        stats['high_risk_detections'] = cursor.fetchone()['count']

        # Most recent scan
        cursor.execute('SELECT timestamp FROM scans ORDER BY id DESC LIMIT 1')
        row = cursor.fetchone()
        stats['last_scan'] = row['timestamp'] if row else None

        # Risk distribution
        cursor.execute('''
            SELECT risk_level, COUNT(*) as count 
            FROM networks 
            GROUP BY risk_level
        ''')
        stats['risk_distribution'] = {row['risk_level']: row['count'] for row in cursor.fetchall()}

        conn.close()
        return stats

    def get_recent_alerts(self, limit=10):
        """Get most recent alerts."""
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM alerts 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))

        alerts = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return alerts

    def get_scan_history(self, limit=50):
        """Get scan session history."""
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM scans 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))

        scans = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return scans

    def get_network_details(self, bssid):
        """Get detailed information about a specific network."""
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM networks 
            WHERE bssid = ? 
            ORDER BY timestamp DESC 
            LIMIT 1
        ''', (bssid,))

        row = cursor.fetchone()
        if row:
            network = dict(row)
            network['risk_factors'] = json.loads(network.get('risk_factors', '[]'))
            conn.close()
            return network

        conn.close()
        return None

    def get_network_history(self, bssid):
        """Get historical observations of a specific network."""
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT signal_strength, encryption, channel, risk_score, timestamp 
            FROM networks 
            WHERE bssid = ? 
            ORDER BY timestamp DESC 
            LIMIT 100
        ''', (bssid,))

        history = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return history

    def get_whitelist(self):
        """Get all whitelisted networks."""
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM whitelist ORDER BY added_date DESC')
        whitelist = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return whitelist

    def add_to_whitelist(self, bssid, ssid='', notes=''):
        """Add a network to the trusted whitelist."""
        conn = self._connect()
        cursor = conn.cursor()

        try:
            cursor.execute('''
                INSERT OR REPLACE INTO whitelist (bssid, ssid, added_date, notes)
                VALUES (?, ?, ?, ?)
            ''', (bssid, ssid, datetime.now().isoformat(), notes))
            conn.commit()
        except sqlite3.IntegrityError:
            pass

        conn.close()

    def remove_from_whitelist(self, bssid):
        """Remove a network from the whitelist."""
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM whitelist WHERE bssid = ?', (bssid,))
        conn.commit()
        conn.close()
