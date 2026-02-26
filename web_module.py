import os, re, webbrowser
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QCheckBox, 
                             QPushButton, QTextEdit, QComboBox, QTableWidget, QTableWidgetItem, 
                             QHeaderView, QMenu, QFileDialog, QTabWidget)
from PyQt6.QtGui import QBrush, QColor
from PyQt6.QtCore import Qt
from scanner_threads import ScannerThread
from ui_components import ModernPanel

class WebTab(QWidget):
    def __init__(self, main_app):
        super().__init__()
        self.main_app = main_app
        self.web_thread = None
        self.wordlist_path = ""
        self.init_ui()

    def init_ui(self):
        main_layout = QHBoxLayout(self)
        main_layout.setSpacing(15)

        # ================= SOL PANEL =================
        left_panel = ModernPanel(); left_panel.setFixedWidth(360)
        left_layout = QVBoxLayout(left_panel); left_layout.setSpacing(10)

        title = QLabel("Web / Directory Scan"); title.setStyleSheet("font-size: 20px; font-weight: bold; color: white;")
        self.target_input = QLineEdit(); self.target_input.setPlaceholderText("http://target.com"); self.target_input.textChanged.connect(self.update_preview)
        self.tool_combo = QComboBox(); self.tool_combo.addItems(["gobuster", "dirsearch", "ffuf"]); self.tool_combo.currentTextChanged.connect(self.update_preview)
        
        wl_h = QHBoxLayout(); self.btn_wl = QPushButton("Wordlist Seç"); self.btn_wl.clicked.connect(self.select_wl); self.wl_label = QLabel("Seçilmedi"); wl_h.addWidget(self.btn_wl); wl_h.addWidget(self.wl_label); left_layout.addLayout(wl_h)

        self.status_filter = QLineEdit(); self.status_filter.setPlaceholderText("Durum (200,301,403)")
        self.threads = QLineEdit(); self.threads.setPlaceholderText("Hız / Thread (50)")
        self.proxy = QLineEdit(); self.proxy.setPlaceholderText("Proxy (http://127.0.0.1:8080)")
        self.recursive_chk = QCheckBox("Recursive Scan"); self.waf_chk = QCheckBox("Detect WAF (Auto Agent)")

        btn_h = QHBoxLayout()
        self.run_btn = QPushButton("Başlat"); self.run_btn.setStyleSheet("background-color: #00ffcc; color: black; font-weight: bold;"); self.run_btn.clicked.connect(self.start_scan)
        self.stop_btn = QPushButton("Durdur"); self.stop_btn.setStyleSheet("background-color: #ff3333; color: white; font-weight: bold;"); self.stop_btn.setEnabled(False); self.stop_btn.clicked.connect(self.stop_scan)
        btn_h.addWidget(self.run_btn); btn_h.addWidget(self.stop_btn)

        left_layout.addWidget(title); left_layout.addWidget(QLabel("Hedef URL:")); left_layout.addWidget(self.target_input)
        left_layout.addWidget(QLabel("Araç:")); left_layout.addWidget(self.tool_combo)
        left_layout.addWidget(QLabel("Filtre:")); left_layout.addWidget(self.status_filter)
        left_layout.addWidget(QLabel("Thread:")); left_layout.addWidget(self.threads)
        left_layout.addWidget(QLabel("Proxy:")); left_layout.addWidget(self.proxy)
        left_layout.addWidget(self.recursive_chk); left_layout.addWidget(self.waf_chk); left_layout.addLayout(btn_h); left_layout.addStretch()

        # ================= SAĞ TARAF (AYRILMIŞ KUTULAR) =================
        right_container = QVBoxLayout(); right_container.setSpacing(15)

        self.top_preview_panel = ModernPanel()
        top_preview_layout = QVBoxLayout(self.top_preview_panel)
        top_preview_layout.addWidget(QLabel("Canlı Komut Önizleme:", styleSheet="color: #00ffcc; font-weight: bold;"))
        self.preview = QTextEdit(); self.preview.setMaximumHeight(55); self.preview.setReadOnly(True)
        self.preview.setStyleSheet("background-color: rgba(0,0,0,120); border: 1px solid #333; color: #00ff00;")
        top_preview_layout.addWidget(self.preview)

        self.bottom_result_panel = ModernPanel()
        bottom_result_layout = QVBoxLayout(self.bottom_result_panel)
        self.results_tabs = QTabWidget()
        self.table = QTableWidget(0, 4); self.table.setHorizontalHeaderLabels(["Durum", "Boyut", "URL", "Ek Bilgi"]); self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu); self.table.customContextMenuRequested.connect(self.show_web_menu)
        self.terminal = QTextEdit(); self.terminal.setReadOnly(True)

        self.results_tabs.addTab(self.table, "Bulunan Endpointler"); self.results_tabs.addTab(self.terminal, "Ham Çıktı (Log)")
        bottom_result_layout.addWidget(self.results_tabs)

        right_container.addWidget(self.top_preview_panel, 1); right_container.addWidget(self.bottom_result_panel, 6)

        main_layout.addWidget(left_panel); main_layout.addLayout(right_container, 3)
        self.update_preview()

    def select_wl(self):
        f, _ = QFileDialog.getOpenFileName(self, "Wordlist Seç"); 
        if f: self.wordlist_path = f; self.wl_label.setText(os.path.basename(f)); self.update_preview()

    def update_preview(self):
        tool = self.tool_combo.currentText(); target = self.target_input.text() or "URL"
        self.preview.setHtml(f"<span style='color:#00ff00'><b>{tool} -u {target} -w ...</b></span>")

    def show_web_menu(self, pos):
        item = self.table.itemAt(pos)
        if item:
            url = self.table.item(item.row(), 2).text()
            menu = QMenu(self); menu.setStyleSheet("QMenu { background: #2a2a35; color: white; border: 1px solid cyan; }")
            act_open = menu.addAction("🌐 Tarayıcıda Aç"); act_nmap = menu.addAction("🛡️ Nmap'e Gönder")
            action = menu.exec(self.table.mapToGlobal(pos))
            if action == act_open: webbrowser.open(url)
            if action == act_nmap: 
                host = url.split("//")[-1].split("/")[0]
                self.main_app.nmap_tab.target_input.setText(host); self.main_app.tabs.setCurrentIndex(0)

    def start_scan(self):
        target = self.target_input.text().strip(); 
        if not target or not self.wordlist_path: return
        tool = self.tool_combo.currentText(); cmd = [tool, "-u", target, "-w", self.wordlist_path]
        if tool == "gobuster": cmd.insert(1, "dir")
        if self.status_filter.text():
            flag = "-s" if tool == "gobuster" else "-mc" if tool == "ffuf" else "-i"
            cmd.extend([flag, self.status_filter.text()])

        self.run_btn.setEnabled(False); self.stop_btn.setEnabled(True); self.table.setRowCount(0); self.terminal.clear()
        self.web_thread = ScannerThread(cmd); self.web_thread.output_signal.connect(lambda t: self.terminal.insertPlainText(t))
        self.web_thread.finished_signal.connect(self.on_finished); self.web_thread.start()

    def on_finished(self, out):
        self.run_btn.setEnabled(True); self.stop_btn.setEnabled(False)
        if out:
            matches = re.findall(r"(200|301|302|403|404)\s+(\d+B|[\d\.]+KB)?\s+(http\S+|/\S+)", out)
            for m in matches:
                r = self.table.rowCount(); self.table.insertRow(r)
                for i, v in enumerate(m):
                    item = QTableWidgetItem(v); 
                    if m[0] == "200": item.setForeground(QBrush(QColor(0, 255, 0)))
                    self.table.setItem(r, i, item)

    def stop_scan(self): 
        if self.web_thread: self.web_thread.stop()