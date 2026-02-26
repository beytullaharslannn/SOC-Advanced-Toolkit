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

        self.ext_input = QLineEdit(); self.ext_input.setPlaceholderText("Uzantı (-x) Örn: php,txt,zip")
        self.ext_input.textChanged.connect(self.update_preview)
        
        self.threads = QLineEdit(); self.threads.setPlaceholderText("Hız / Thread (50)")
        self.threads.textChanged.connect(self.update_preview)
        
        self.recursive_chk = QCheckBox("Recursive Scan"); self.waf_chk = QCheckBox("Detect WAF (Auto Agent)")

        self.progress_label = QLabel("İlerleme: Bekleniyor...")
        self.progress_label.setStyleSheet("color: #ffaa00; font-weight: bold; font-size: 14px; margin-top: 5px;")

        btn_h = QHBoxLayout()
        self.run_btn = QPushButton("Başlat"); self.run_btn.setStyleSheet("background-color: #00ffcc; color: black; font-weight: bold;"); self.run_btn.clicked.connect(self.start_scan)
        self.stop_btn = QPushButton("Durdur"); self.stop_btn.setStyleSheet("background-color: #ff3333; color: white; font-weight: bold;"); self.stop_btn.setEnabled(False); self.stop_btn.clicked.connect(self.stop_scan)
        btn_h.addWidget(self.run_btn); btn_h.addWidget(self.stop_btn)

        left_layout.addWidget(title); left_layout.addWidget(QLabel("Hedef URL:")); left_layout.addWidget(self.target_input)
        left_layout.addWidget(QLabel("Araç:")); left_layout.addWidget(self.tool_combo)
        left_layout.addWidget(QLabel("Uzantılar:")); left_layout.addWidget(self.ext_input)
        left_layout.addWidget(QLabel("Thread:")); left_layout.addWidget(self.threads)
        left_layout.addWidget(self.recursive_chk); left_layout.addWidget(self.waf_chk)
        left_layout.addWidget(self.progress_label)
        left_layout.addLayout(btn_h); left_layout.addStretch()

        # ================= SAĞ TARAF (AYRILMIŞ KUTULAR) =================
        right_container = QVBoxLayout(); right_container.setSpacing(15)

        self.top_preview_panel = ModernPanel()
        top_preview_layout = QVBoxLayout(self.top_preview_panel)
        top_preview_layout.addWidget(QLabel("Canlı Komut Önizleme (Düzenlenebilir):", styleSheet="color: #00ffcc; font-weight: bold;"))
        
        self.preview = QTextEdit(); self.preview.setMaximumHeight(55); self.preview.setReadOnly(False)
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
        options = QFileDialog.Option.DontUseNativeDialog
        f, _ = QFileDialog.getOpenFileName(self, "Wordlist Seç", "", "All Files (*);;Text Files (*.txt)", options=options)
        if f: 
            self.wordlist_path = f
            self.wl_label.setText(os.path.basename(f)) 
            self.update_preview()

    def update_preview(self):
        tool = self.tool_combo.currentText()
        target = self.target_input.text().strip() or "URL"
        wl = self.wordlist_path if self.wordlist_path else "..."
        
        cmd = f"{tool} "
        if tool == "gobuster":
            cmd += "dir "
            
        cmd += f"-u {target} -w {wl} "
        
        if self.ext_input.text().strip():
            cmd += f"-x {self.ext_input.text().strip()} "
            
        if self.threads.text().strip():
            cmd += f"-t {self.threads.text().strip()} "
            
        self.preview.setPlainText(cmd.strip()) 

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
        raw_cmd = self.preview.toPlainText().strip()
        if not raw_cmd or "URL" in raw_cmd or "..." in raw_cmd: 
            self.terminal.append("[-] HATA: Lütfen geçerli bir URL ve Wordlist seçin.")
            return
            
        cmd = raw_cmd.split() 
        self.run_btn.setEnabled(False); self.stop_btn.setEnabled(True); self.table.setRowCount(0); self.terminal.clear()
        self.progress_label.setText("İlerleme: Tarama Başladı...")
        
        self.web_thread = ScannerThread(cmd)
        self.web_thread.output_signal.connect(self.handle_output) 
        self.web_thread.finished_signal.connect(self.on_finished)
        self.web_thread.start()

    # --- YENİ EKLENEN CANLI ANALİZ FONKSİYONLARI ---
    
    def handle_output(self, text):
        self.terminal.insertPlainText(text) # Ham loga yazmaya devam eder
        
        # 1. Canlı İlerleme Çubuğu (Örn: 154 / 4600)
        match_prog = re.search(r'(\d+\s*/\s*\d+)', text)
        if match_prog:
            self.progress_label.setText(f"İlerleme: {match_prog.group(1)}")

        # 2. Canlı Endpoint Yakalayıcı (Standart Format)
        matches = re.findall(r"(200|301|302|403|404|500)\s+(\d+B|[\d\.]+KB)?\s+(http\S+|/\S+)", text)
        for m in matches:
            self.add_table_row(status=m[0], size=m[1], url=m[2])

        # 3. Canlı Endpoint Yakalayıcı (Gobuster Özel Formatı: /admin (Status: 301) [Size: 312])
        gobuster_matches = re.findall(r"(http\S+|/\S+)\s*\(Status:\s*(200|301|302|403|404|500)\)\s*\[Size:\s*(\d+)\]", text)
        for gm in gobuster_matches:
            self.add_table_row(status=gm[1], size=gm[2], url=gm[0])

    def add_table_row(self, status, size, url):
        r = self.table.rowCount()
        self.table.insertRow(r)
        
        item_status = QTableWidgetItem(status)
        # Durum kodlarına göre havalı renklendirmeler
        if status == "200": item_status.setForeground(QBrush(QColor(0, 255, 0))) # Yeşil
        elif status in ["301", "302"]: item_status.setForeground(QBrush(QColor(255, 165, 0))) # Turuncu
        elif status in ["403", "404", "500"]: item_status.setForeground(QBrush(QColor(255, 51, 51))) # Kırmızı
        
        self.table.setItem(r, 0, item_status)
        self.table.setItem(r, 1, QTableWidgetItem(size))
        self.table.setItem(r, 2, QTableWidgetItem(url))

    # -----------------------------------------------

    def on_finished(self, out):
        # Tarama bitince sadece butonları sıfırlarız, tabloyu zaten canlı doldurduk.
        self.run_btn.setEnabled(True); self.stop_btn.setEnabled(False)
        self.progress_label.setText("İlerleme: Tamamlandı!")

    def stop_scan(self): 
        if self.web_thread: 
            self.web_thread.stop()
            self.progress_label.setText("İlerleme: Durduruldu!")