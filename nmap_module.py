import re, json
from datetime import datetime
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QCheckBox, 
                             QPushButton, QTextEdit, QComboBox, QTableWidget, QTableWidgetItem, 
                             QHeaderView, QMenu, QFileDialog, QTabWidget, QSystemTrayIcon, QStyle)
from PyQt6.QtGui import QBrush, QColor, QTextDocument, QPdfWriter
from PyQt6.QtCore import Qt
from scanner_threads import ScannerThread
from ui_components import ModernPanel

class NmapTab(QWidget):
    def __init__(self, cve_tab_ref=None): # BURAYA PARAMETRE EKLENDİ
        super().__init__()
        self.cve_tab_ref = cve_tab_ref # REFERANSI KAYDEDİYORUZ
        self.nmap_thread = None
        self.init_ui()

    def init_ui(self):
        layout = QHBoxLayout(self)
        layout.setSpacing(15) # Paneller arası boşluk
        
        # ================= SOL PANEL (TÜM AYARLAR) =================
        left_panel = ModernPanel(); left_panel.setFixedWidth(350); left_layout = QVBoxLayout(left_panel)
        left_layout.setSpacing(10)
        
        title = QLabel("Nmap Tarama Ayarları")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #ffffff;")
        left_layout.addWidget(title)
        
        self.target_input = QLineEdit(); self.target_input.setPlaceholderText("Hedef IP veya Domain")
        self.target_input.textChanged.connect(self.update_live_preview)
        left_layout.addWidget(self.target_input)
        
        left_layout.addWidget(QLabel("Tarama Profili:", styleSheet="color:#00bfff; font-weight:bold;"))
        self.profile_combo = QComboBox(); self.profile_combo.addItems(["Custom (Kendin Belirle)", "Quick Scan", "Full Port Scan", "Stealth Scan", "Vulnerability Scan"])
        self.profile_combo.currentIndexChanged.connect(self.apply_scan_profile)
        left_layout.addWidget(self.profile_combo)
        
        # Timing ve Script Seçimi
        row_opts = QHBoxLayout()
        self.timing_combo = QComboBox(); self.timing_combo.addItems(["T3 (Normal)", "T0", "T1", "T2", "T4", "T5"])
        self.timing_combo.currentTextChanged.connect(self.update_live_preview)
        self.script_combo = QComboBox(); self.script_combo.addItems(["Script Yok", "default", "vuln", "safe", "discovery", "auth"])
        self.script_combo.currentTextChanged.connect(self.update_live_preview)
        row_opts.addWidget(self.timing_combo); row_opts.addWidget(self.script_combo)
        left_layout.addLayout(row_opts)
        
        # Checkboxlar
        self.chk_sS = QCheckBox("-sS (Syn Scan)"); self.chk_sS.stateChanged.connect(self.update_live_preview)
        self.chk_sV = QCheckBox("-sV (Version)"); self.chk_sV.stateChanged.connect(self.update_live_preview)
        self.chk_sC = QCheckBox("-sC (Default Scripts)"); self.chk_sC.stateChanged.connect(self.update_live_preview)
        self.chk_A  = QCheckBox("-A (Aggressive)"); self.chk_A.stateChanged.connect(self.update_live_preview)
        self.chk_O  = QCheckBox("-O (OS Detect)"); self.chk_O.stateChanged.connect(self.update_live_preview)
        self.chk_Pn = QCheckBox("-Pn (No Ping)"); self.chk_Pn.stateChanged.connect(self.update_live_preview)
        
        self.checks = [self.chk_sS, self.chk_sV, self.chk_sC, self.chk_A, self.chk_O, self.chk_Pn]
        for chk in self.checks:
            left_layout.addWidget(chk)
            
        self.port_input = QLineEdit(); self.port_input.setPlaceholderText("Spesifik Portlar (Örn: 80,443)")
        self.port_input.textChanged.connect(self.update_live_preview); left_layout.addWidget(self.port_input)
        
        self.custom_input = QLineEdit(); self.custom_input.setPlaceholderText("Custom Parametre")
        self.custom_input.textChanged.connect(self.update_live_preview); left_layout.addWidget(self.custom_input)
        
        # Butonlar
        btn_layout = QHBoxLayout()
        self.run_btn = QPushButton("Başlat"); self.run_btn.setStyleSheet("background-color: #00bfff; color: black; font-weight: bold;"); self.run_btn.clicked.connect(self.start_scan)
        self.stop_btn = QPushButton("Durdur"); self.stop_btn.setEnabled(False); self.stop_btn.setStyleSheet("background-color: #ff3333; color: white;"); self.stop_btn.clicked.connect(self.stop_scan)
        btn_layout.addWidget(self.run_btn); btn_layout.addWidget(self.stop_btn); left_layout.addLayout(btn_layout)
        
        exp_h = QHBoxLayout(); self.btn_pdf = QPushButton("PDF Çıktı"); self.btn_json = QPushButton("JSON Çıktı")
        self.btn_pdf.clicked.connect(self.export_pdf); self.btn_json.clicked.connect(self.export_json)
        exp_h.addWidget(self.btn_pdf); exp_h.addWidget(self.btn_json); left_layout.addLayout(exp_h)
        left_layout.addStretch()

        # ================= SAĞ TARAF (AYRILMIŞ 2 KUTU) =================
        right_container = QVBoxLayout(); right_container.setSpacing(15)
        
        # ÜST KUTU: Canlı Önizleme
        self.top_box = ModernPanel(); top_layout = QVBoxLayout(self.top_box)
        top_layout.addWidget(QLabel("Canlı Komut Önizleme:", styleSheet="color: #00ffcc; font-weight: bold;"))
        self.live_preview = QTextEdit(); self.live_preview.setMaximumHeight(55); self.live_preview.setReadOnly(True)
        self.live_preview.setStyleSheet("background-color: rgba(0,0,0,100); border: 1px solid #333;")
        top_layout.addWidget(self.live_preview)
        
        # ALT KUTU: Sonuçlar
        self.bottom_box = ModernPanel(); bottom_layout = QVBoxLayout(self.bottom_box)
        self.results_tabs = QTabWidget()
        self.terminal = QTextEdit(); self.terminal.setReadOnly(True)
        self.table = QTableWidget(0, 4); self.table.setHorizontalHeaderLabels(["Port", "Durum", "Servis", "Versiyon"]); self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu); self.table.customContextMenuRequested.connect(self.show_port_context_menu)
        self.history_log = QTextEdit(); self.history_log.setReadOnly(True)
        
        self.results_tabs.addTab(self.terminal, "Terminal"); self.results_tabs.addTab(self.table, "Analiz Tablosu"); self.results_tabs.addTab(self.history_log, "Loglar")
        bottom_layout.addWidget(self.results_tabs)
        
        right_container.addWidget(self.top_box, 1); right_container.addWidget(self.bottom_box, 5)
        
        layout.addWidget(left_panel); layout.addLayout(right_container, 3)
        self.update_live_preview()
        
        # BİLDİRİM SİSTEMİ BAŞLATMA
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))
        self.tray_icon.show()

    def log_event(self, text):
        now = datetime.now().strftime("%H:%M:%S")
        self.history_log.append(f"[{now}] {text}")

    def update_live_preview(self):
        target = self.target_input.text().strip() or "HOST"
        timing = self.timing_combo.currentText().split(" ")[0]
        script = self.script_combo.currentText()
        cmd = f"nmap -{timing} "
        if self.chk_sS.isChecked(): cmd += "-sS "
        if self.chk_sV.isChecked(): cmd += "-sV "
        if self.chk_sC.isChecked(): cmd += "-sC "
        if self.chk_A.isChecked(): cmd += "-A "
        if self.chk_O.isChecked(): cmd += "-O "
        if self.chk_Pn.isChecked(): cmd += "-Pn "
        if script != "Script Yok": cmd += f"--script={script} "
        if self.port_input.text(): cmd += f"-p {self.port_input.text()} "
        if self.custom_input.text(): cmd += f"{self.custom_input.text()} "
        self.live_preview.setHtml(f"<span style='color:#00ff00'><b>{cmd}</b></span> <span style='color:#ff4500'>{target}</span>")

    def apply_scan_profile(self, index):
        p = self.profile_combo.currentText()
        for chk in self.checks: chk.setChecked(False)
        if p == "Quick Scan": self.custom_input.setText("-F"); self.timing_combo.setCurrentText("T4")
        elif p == "Full Port Scan": self.chk_sV.setChecked(True); self.chk_A.setChecked(True); self.port_input.setText("1-65535")
        elif p == "Stealth Scan": self.chk_sS.setChecked(True); self.chk_Pn.setChecked(True)
        elif p == "Vulnerability Scan": self.chk_sV.setChecked(True); self.script_combo.setCurrentText("vuln")
        self.update_live_preview()

    def start_scan(self):
        target = self.target_input.text().strip()
        if not target: return
        cmd = ["nmap", f"-{self.timing_combo.currentText().split(' ')[0]}"]
        if self.chk_sS.isChecked(): cmd.append("-sS")
        if self.chk_sV.isChecked(): cmd.append("-sV")
        if self.chk_sC.isChecked(): cmd.append("-sC")
        if self.chk_A.isChecked(): cmd.append("-A")
        if self.chk_O.isChecked(): cmd.append("-O")
        if self.chk_Pn.isChecked(): cmd.append("-Pn")
        if self.script_combo.currentText() != "Script Yok": cmd.append(f"--script={self.script_combo.currentText()}")
        if self.port_input.text(): cmd.extend(["-p", self.port_input.text()])
        if self.custom_input.text(): cmd.extend(self.custom_input.text().split())
        cmd.append(target)
        
        self.run_btn.setEnabled(False); self.stop_btn.setEnabled(True); self.terminal.clear(); self.table.setRowCount(0)
        self.log_event(f"Tarama Başlatıldı: {' '.join(cmd)}")
        self.nmap_thread = ScannerThread(cmd)
        self.nmap_thread.output_signal.connect(lambda t: self.terminal.insertPlainText(t))
        self.nmap_thread.finished_signal.connect(self.on_finished); self.nmap_thread.start()

    def on_finished(self, out):
        self.run_btn.setEnabled(True); self.stop_btn.setEnabled(False)
        if out: 
            self.parse_table(out)
            self.log_event("Tarama başarıyla tamamlandı.")
            # BİLDİRİM FIRLATILIYOR:
            self.tray_icon.showMessage("🛡️ Nmap Tarama", "Tarama başarıyla tamamlandı!", QSystemTrayIcon.MessageIcon.Information, 3000)
        else:
            self.log_event("Tarama durduruldu veya hata oluştu.")

    def parse_table(self, text):
        matches = re.findall(r"^(\d+/(?:tcp|udp))\s+(open|filtered)\s+([\w\-]+)\s+(.*)$", text, re.M)
        for m in matches:
            r = self.table.rowCount(); self.table.insertRow(r)
            for i, val in enumerate(m): 
                item = QTableWidgetItem(val)
                if val == "open": item.setForeground(QBrush(QColor(0,255,0)))
                self.table.setItem(r, i, item)

    def stop_scan(self): 
        if self.nmap_thread: self.nmap_thread.stop()

    def show_port_context_menu(self, pos):
        item = self.table.itemAt(pos)
        if item:
            row = item.row()
            port = self.table.item(row, 0).text().split("/")[0]
            service = self.table.item(row, 2).text() # Tablodan servis adını çeker
            version = self.table.item(row, 3).text() # Tablodan versiyonu çeker
            
            menu = QMenu(self)
            menu.setStyleSheet("QMenu { background:#2a2a35; color:white; }")
            
            # Seçenek 1: Eski özelliğin
            act_analyze = menu.addAction(f"Port {port} Detaylı Analiz")
            
            # Seçenek 2: YENİ EKLENEN CVE ARAMASI
            search_term = f"{service} {version}".strip()
            act_cve = menu.addAction(f"🔍 '{search_term}' için CVE Ara")
            
            action = menu.exec(self.table.mapToGlobal(pos))
            
            if action == act_analyze:
                self.port_input.setText(port)
                self.chk_A.setChecked(True)
                self.start_scan()
            elif action == act_cve and self.cve_tab_ref:
                # KANKA: Tıklanınca aramayı CVE sekmesine gönderir
                self.cve_tab_ref.external_search(search_term)
                # Ekranı otomatik olarak CVE sekmesine kaydırır (Index 1)
                self.parentWidget().parentWidget().setCurrentIndex(1)
                
    def export_pdf(self):
        options = QFileDialog.Option.DontUseNativeDialog
        f, _ = QFileDialog.getSaveFileName(self, "PDF Kaydet", "", "PDF Files (*.pdf)", options=options)
        if f:
            doc = QTextDocument(); doc.setHtml(f"<h1>Nmap Raporu</h1><p>Hedef: {self.target_input.text()}</p><hr>" + self.terminal.toHtml())
            writer = QPdfWriter(f); doc.print(writer); self.log_event(f"Rapor Kaydedildi: {f}")

    def export_json(self):
        options = QFileDialog.Option.DontUseNativeDialog
        f, _ = QFileDialog.getSaveFileName(self, "JSON Kaydet", "", "JSON Files (*.json)", options=options)
        if f:
            with open(f, 'w') as jf: json.dump({"target": self.target_input.text(), "date": str(datetime.now()), "raw_output": self.terminal.toPlainText()}, jf, indent=4)
            self.log_event(f"Veriler Kaydedildi: {f}")
