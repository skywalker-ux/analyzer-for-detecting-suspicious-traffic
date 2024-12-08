import sys
import socket
import psutil
from PyQt5 import QtWidgets, QtCore


class NetworkMonitor(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Traffic Monitor")
        self.setGeometry(100, 100, 800, 400)

        self.layout = QtWidgets.QVBoxLayout()
        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            ["Локальные адреса", "Удаленные адреса", "Статус", "Протокол", "Подозрительный"])
        self.layout.addWidget(self.table)
        self.setLayout(self.layout)

        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.update_connections)
        self.timer.start(2000)

    def update_connections(self):
        self.table.setRowCount(0)
        connections = psutil.net_connections(kind='inet')

        for conn in connections:

            suspicious = self.is_suspicious(conn)
            row_position = self.table.rowCount()
            self.table.insertRow(row_position)

            local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "Отсутствует"
            self.table.setItem(row_position, 0, QtWidgets.QTableWidgetItem(local_addr))

            remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "Отсутствует"
            self.table.setItem(row_position, 1, QtWidgets.QTableWidgetItem(remote_addr))

            self.table.setItem(row_position, 2, QtWidgets.QTableWidgetItem(conn.status))

            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            self.table.setItem(row_position, 3, QtWidgets.QTableWidgetItem(proto))

            suspicion_text = "Да" if suspicious else "Нет"
            item = QtWidgets.QTableWidgetItem(suspicion_text)
            if suspicious:
                item.setBackground(QtCore.Qt.red)
            self.table.setItem(row_position, 4, item)

    def is_suspicious(self, conn):

        if conn.raddr:

            suspicious_ports = {6666, 4444, 8888, 5555}
            if conn.raddr.port in suspicious_ports:
                return True
            trusted_networks = ["192.168.", "10.0."]
            if not any(conn.raddr.ip.startswith(net) for net in trusted_networks):
                return True
        return False


app = QtWidgets.QApplication(sys.argv)
window = NetworkMonitor()
window.show()
sys.exit(app.exec_())