import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QTabWidget
# DOĞRU İSİMLER BUNLAR:
from ui_components import AnimatedBackground 
from nmap_module import NmapTab
from web_module import WebTab
from brute_module import BruteTab
from cve_module import CVETab
from crypto_module import CryptoTab
class SecurityApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SOC - Advanced Security Toolkit")
        self.resize(1300, 900)

        # Ana Konteynır
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget); self.main_layout.setContentsMargins(0, 0, 0, 0)

        # Arka Plan
        self.bg = AnimatedBackground(self.central_widget); self.bg.resize(self.size())

        # UI Katmanı (Arka planın üstünde duracak)
        self.ui_layer = QWidget(self.central_widget); self.ui_layout = QVBoxLayout(self.ui_layer); self.ui_layout.setContentsMargins(15, 15, 15, 15)

        self.setup_styles()

        self.tabs = QTabWidget()
        # ÖNCE CVE TAB'INI OLUŞTURUYORUZ
        self.cve_tab = CVETab()
        # SONRA NMAP TAB'INA BU REFERANSI (KÖPRÜYÜ) VERİYORUZ
        self.nmap_tab = NmapTab(self.cve_tab) 
        self.web_tab = WebTab(self)
        self.brute_tab = BruteTab()
        self.crypto_tab = CryptoTab()
        
        
        self.tabs.addTab(self.nmap_tab, "Nmap Gelişmiş Tarama")
        self.tabs.addTab(self.cve_tab, "CVE Araştırma")
        self.tabs.addTab(self.web_tab, "Dizin / Web Tarama")
        self.tabs.addTab(self.brute_tab, "Brute Force (Hydra)")
        self.tabs.addTab(self.crypto_tab, "Kriptografi & CTF")
        self.ui_layout.addWidget(self.tabs)

    def setup_styles(self):
        self.setStyleSheet("""
            QWidget { color: #e0e0e0; font-family: 'Segoe UI', Arial; }
            QTabWidget::pane { border: none; background: transparent; }
            QTabBar::tab { background: rgba(40, 40, 50, 160); color: white; padding: 12px 25px; border-radius: 8px; margin-right: 5px; font-weight: bold; }
            QTabBar::tab:selected { background: rgba(0, 150, 255, 190); border: 1px solid cyan; }
            QLineEdit, QTextEdit, QComboBox { background-color: rgba(15, 15, 20, 160); border: 1px solid rgba(255, 255, 255, 35); border-radius: 6px; padding: 8px; color: #00ffcc; font-family: Consolas; }
            QPushButton { background-color: rgba(0, 120, 215, 185); border: none; border-radius: 6px; padding: 10px; font-weight: bold; color: white; }
            QPushButton:hover { background-color: rgba(0, 150, 255, 225); }
            QTableWidget { background-color: rgba(10, 10, 15, 210); alternate-background-color: rgba(20, 20, 25, 210); color: #fff; border: 1px solid rgba(255,255,255,35); }
            QHeaderView::section { background-color: rgba(0, 120, 215, 160); color: white; font-weight: bold; border: 1px solid rgba(255,255,255,20); }
            QCheckBox { spacing: 8px; font-weight: bold; font-size: 13px; }
            QCheckBox::indicator { width: 18px; height: 18px; border-radius: 4px; border: 1px solid #555; background: #111; }
            QCheckBox::indicator:checked { background: #00bfff; border: 1px solid cyan; }
        """)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.bg.resize(event.size())
        self.ui_layer.resize(event.size())

if __name__ == "__main__":
    app = QApplication(sys.argv); window = SecurityApp(); window.show(); sys.exit(app.exec())