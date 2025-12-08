import sys
from datetime import datetime

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QMessageBox,
)

from scanner import scan_network

# Якщо ти вже зробив storage.py за моїм попереднім кодом – імпортуй його
# Якщо ще ні – тимчасово можеш закоментувати цей імпорт і виклики init_db/save_scan
from storage import init_db, save_scan


class ScanWorker(QThread):
    """
    Окремий потік для сканування, щоб не підвисав інтерфейс.
    """
    finished = Signal(list, str, datetime, datetime)  # hosts, network, started_at, finished_at

    def __init__(self, network: str, parent=None):
        super().__init__(parent)
        self.network = network

    def run(self):
        started_at = datetime.now()
        hosts = scan_network(self.network)  # використовуємо твою функцію
        finished_at = datetime.now()
        self.finished.emit(hosts, self.network, started_at, finished_at)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Сканер локальної мережі (прототип диплома)")
        self.resize(800, 500)

        # Ініціалізуємо БД (якщо storage підключений)
        init_db()

        self.worker: ScanWorker | None = None

        # --- Головний віджет і layout ---
        central = QWidget(self)
        self.setCentralWidget(central)

        main_layout = QVBoxLayout()
        central.setLayout(main_layout)

        # --- Верхня панель: підмережа + кнопка ---
        top_layout = QHBoxLayout()

        self.network_label = QLabel("Підмережа:")
        self.network_input = QLineEdit()
        self.network_input.setPlaceholderText("наприклад, 192.168.0.0/24")
        self.network_input.setText("192.168.0.0/24")  # значення за замовчуванням

        self.scan_button = QPushButton("Сканувати")
        self.scan_button.clicked.connect(self.on_scan_clicked)

        top_layout.addWidget(self.network_label)
        top_layout.addWidget(self.network_input, stretch=1)
        top_layout.addWidget(self.scan_button)

        main_layout.addLayout(top_layout)

         # --- Таблиця з результатами ---
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels([
            "IP-адреса активного хоста",
            "Відкриті TCP-порти",
            "Тип вузла / сервіси"
        ])
        self.table.horizontalHeader().setStretchLastSection(True)


        main_layout.addWidget(self.table)

        # --- Статус + info внизу ---
        self.status_label = QLabel("Готово до сканування.")
        self.status_label.setAlignment(Qt.AlignLeft)

        self.scan_id_label = QLabel("")  # сюди виведемо ID скану з БД
        self.scan_id_label.setAlignment(Qt.AlignRight)

        bottom_layout = QHBoxLayout()
        bottom_layout.addWidget(self.status_label)
        bottom_layout.addWidget(self.scan_id_label)

        main_layout.addLayout(bottom_layout)

    # ---------- Обробники подій ----------

    def on_scan_clicked(self):
        network = self.network_input.text().strip()
        if not network:
            QMessageBox.warning(self, "Помилка", "Будь ласка, введіть підмережу.")
            return

        # Блокуємо елементи на час сканування
        self.scan_button.setEnabled(False)
        self.network_input.setEnabled(False)
        self.status_label.setText(f"Сканування {network} ...")

        # Очищаємо попередню таблицю
        self.table.setRowCount(0)
        self.scan_id_label.setText("")

        # Стартуємо потік зі сканером
        self.worker = ScanWorker(network)
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.start()

    def on_scan_finished(self, hosts, network, started_at, finished_at):
        """
        Викликається, коли ScanWorker закінчив роботу.

        hosts – список словників:
            { "ip": "...", "open_ports": [...], "role": "..." }
        """
        # Розблоковуємо кнопки
        self.scan_button.setEnabled(True)
        self.network_input.setEnabled(True)

        # Заповнюємо таблицю
        self.table.setRowCount(len(hosts))
        for row, host in enumerate(hosts):
            ip = host.get("ip", "")
            ports = host.get("open_ports", [])
            role = host.get("role", "")

            ports_str = ", ".join(str(p) for p in ports) if ports else "—"
            role_str = role if role else "—"

            ip_item = QTableWidgetItem(ip)
            ip_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)

            ports_item = QTableWidgetItem(ports_str)
            ports_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)

            role_item = QTableWidgetItem(role_str)
            role_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)

            self.table.setItem(row, 0, ip_item)
            self.table.setItem(row, 1, ports_item)
            self.table.setItem(row, 2, role_item)

        # Зберігаємо в БД
        scan_id = save_scan(network, started_at, finished_at, hosts)

        # Оновлюємо статуси
        if hosts:
            self.status_label.setText(
                f"Сканування завершено. Знайдено {len(hosts)} активних хостів."
            )
        else:
            self.status_label.setText(
                "Сканування завершено. Активних хостів не знайдено."
            )

        self.scan_id_label.setText(f"ID останнього скану: {scan_id}")




def run_app():
    """
    Запуск графічного інтерфейсу.
    Викликається з main.py
    """
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
