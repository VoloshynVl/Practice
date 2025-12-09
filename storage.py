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


# Проста мапа: номер порту -> назва сервісу (для таблиці services)
_PORT_SERVICE_MAP = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
}


def _guess_service(port: int) -> str:
    """
    Повертає назву сервісу для типових портів.
    Якщо порт невідомий – повертає 'невідомий сервіс'.
    """
    return _PORT_SERVICE_MAP.get(port, "невідомий сервіс")


def init_db():
    """
    Створює файл бази даних і таблиці, якщо їх ще немає.
    Викликається один раз при старті програми (у MainWindow).
    """
    conn = _get_connection()
    cur = conn.cursor()

    # Таблиця сканувань
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL,
            duration_sec INTEGER NOT NULL DEFAULT 0,
            host_count INTEGER NOT NULL DEFAULT 0
        );
        """
    )

    # Таблиця активних хостів для кожного сканування
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            hostname TEXT NOT NULL DEFAULT '',
            open_ports TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT '',
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        );
        """
    )

    # НОВА таблиця сервісів (портів) для кожного хоста
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL DEFAULT 'tcp',
            service TEXT NOT NULL DEFAULT '',
            state TEXT NOT NULL DEFAULT 'open',
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
        );
        """
    )

    conn.commit()
    conn.close()


def save_scan(
    network: str,
    started_at: datetime,
    finished_at: datetime,
    hosts: list[dict],
) -> int:
    """
    Зберігає одне сканування у базу:
      - запис у scans
      - список IP + відкриті порти + роль у hosts
      - детальну інформацію про кожен порт у services

    hosts – список словників:
        {
          "ip": "192.168.0.10",
          "open_ports": [80, 443],
          "role": "web-сервер",
          "hostname": "my-pc"   # (опційно)
        }

    Повертає id доданого сканування (щоб показати в інтерфейсі).
    """
    conn = _get_connection()
    cur = conn.cursor()

    # Обчислюємо тривалість сканування в секундах
    duration_sec = int((finished_at - started_at).total_seconds())

    # 1. Додаємо запис про саме сканування
    cur.execute(
        """
        INSERT INTO scans (network, started_at, finished_at, duration_sec, host_count)
        VALUES (?, ?, ?, ?, ?);
        """,
        (
            network,
            started_at.isoformat(),
            finished_at.isoformat(),
            duration_sec,
            len(hosts),
        ),
    )
    scan_id = cur.lastrowid

    # 2. Додаємо всі знайдені хости + сервіси для кожного хоста
    for host in hosts:
        ip = host.get("ip", "")
        ports = host.get("open_ports", [])
        role = host.get("role", "")
        hostname = host.get("hostname", "")

        ports_str = ",".join(str(p) for p in ports) if ports else ""

        # Запис у таблицю hosts
        cur.execute(
            """
            INSERT INTO hosts (scan_id, ip, hostname, open_ports, role)
            VALUES (?, ?, ?, ?, ?);
            """,
            (scan_id, ip, hostname, ports_str, role),
        )
        host_id = cur.lastrowid

        # Записи у таблицю services (по одному рядку на кожен порт)
        for port in ports:
            try:
                port_int = int(port)
            except (TypeError, ValueError):
                continue

            service_name = _guess_service(port_int)

            cur.execute(
                """
                INSERT INTO services (host_id, port, protocol, service, state)
                VALUES (?, ?, ?, ?, ?);
                """,
                (host_id, port_int, "tcp", service_name, "open"),
            )

    conn.commit()
    conn.close()

    return scan_id
