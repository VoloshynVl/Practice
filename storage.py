import sqlite3
from datetime import datetime
from pathlib import Path

# Файл бази даних буде лежати поруч з .py-файлами
DB_PATH = Path(__file__).with_name("scanner.db")


def _get_connection():
    """
    Внутрішня функція: відкриває з'єднання з базою даних.
    Кожен раз, коли треба щось зробити з БД, викликаємо її.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """
    Створює файл бази даних і таблиці, якщо їх ще немає.
    Викликається один раз при старті програми (у MainWindow).
    """
    conn = _get_connection()
    cur = conn.cursor()

    # Таблиця сканувань
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL,
            host_count INTEGER NOT NULL DEFAULT 0
        );
    """)

    # Таблиця активних хостів для кожного сканування
    cur.execute("""
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            open_ports TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT '',
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        );
    """)

    conn.commit()
    conn.close()


def save_scan(network: str,
              started_at: datetime,
              finished_at: datetime,
              hosts: list[dict]) -> int:
    """
    Зберігає одне сканування у базу:
      - запис у scans
      - список IP + відкриті порти + роль у hosts

    hosts – список словників:
        { "ip": "192.168.0.10", "open_ports": [80, 443], "role": "web-сервер" }

    Повертає id доданого сканування (щоб показати в інтерфейсі).
    """
    conn = _get_connection()
    cur = conn.cursor()

    # 1. Додаємо запис про саме сканування
    cur.execute(
        """
        INSERT INTO scans (network, started_at, finished_at, host_count)
        VALUES (?, ?, ?, ?);
        """,
        (network, started_at.isoformat(), finished_at.isoformat(), len(hosts))
    )
    scan_id = cur.lastrowid

    # 2. Додаємо всі знайдені хости
    for host in hosts:
        ip = host.get("ip", "")
        ports = host.get("open_ports", [])
        role = host.get("role", "")

        ports_str = ",".join(str(p) for p in ports) if ports else ""

        cur.execute(
            "INSERT INTO hosts (scan_id, ip, open_ports, role) VALUES (?, ?, ?, ?);",
            (scan_id, ip, ports_str, role)
        )

    conn.commit()
    conn.close()

    return scan_id
