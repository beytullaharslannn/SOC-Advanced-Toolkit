import os, re, shlex
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                             QPushButton, QComboBox, QFileDialog, QTextEdit, QSystemTrayIcon, QStyle)
from PyQt6.QtCore import Qt
from scanner_threads import ScannerThread
from ui_components import ModernPanel

class BruteTab(QWidget):
    def __init__(self):
        super().__init__()
        self.pass_path = ""
        self.brute_thread = None
        self.init_ui()

    def init_ui(self):
        main_layout = QHBoxLayout(self)
        main_layout.setSpacing(15)

        # ================= SOL PANEL (AYARLAR) =================
        left_panel = ModernPanel(); left_panel.setFixedWidth(350)
        left_layout = QVBoxLayout(left_panel); left_layout.setSpacing(12)

        title = QLabel("Brute Force / Hydra"); title.setStyleSheet("font-size: 18px; font-weight: bold; color: white;")
        
        self.target_input = QLineEdit(); self.target_input.setPlaceholderText("Hedef IP veya Domain")
        self.target_input.textChanged.connect(self.update_preview)
        
        self.service_combo = QComboBox()
        self.service_combo.addItems(["ssh", "ftp", "http-post-form", "https-post-form", "telnet", "mysql"])
        self.service_combo.currentTextChanged.connect(self.toggle_http_fields)
        self.service_combo.currentTextChanged.connect(self.update_preview)
        
        self.user_input = QLineEdit(); self.user_input.setPlaceholderText("Kullanıcı Adı (Örn: admin)")
        self.user_input.textChanged.connect(self.update_preview)
        
        # --- HTTP FORM YAPILANDIRICI (DÜZELTİLDİ) ---
        self.http_container = QWidget()
        http_vbox = QVBoxLayout(self.http_container); http_vbox.setContentsMargins(0,0,0,0)
        
        # Giriş Sayfası Yolu
        http_vbox.addWidget(QLabel("Giriş Sayfası Yolu:", styleSheet="color: #ffaa00; font-size: 11px;"))
        self.http_path = QLineEdit(); self.http_path.setText("/login.php")
        http_vbox.addWidget(self.http_path) # <-- Eklendi!
        
        # Post Verisi
        http_vbox.addWidget(QLabel("Post Verisi (Parametreler):", styleSheet="color: #ffaa00; font-size: 11px;"))
        self.http_post_data = QLineEdit(); self.http_post_data.setText("user=^USER^&pass=^PASS^")
        http_vbox.addWidget(self.http_post_data) # <-- Eklendi!
        
        # Hata Mesajı
        http_vbox.addWidget(QLabel("Hata Mesajı (Sitede Görünen):", styleSheet="color: #ffaa00; font-size: 11px;"))
        self.http_error_msg = QLineEdit(); self.http_error_msg.setPlaceholderText("Wrong password")
        http_vbox.addWidget(self.http_error_msg) # <-- Eklendi!
        
        # Event bağlantıları
        self.http_path.textChanged.connect(self.update_preview)
        self.http_post_data.textChanged.connect(self.update_preview)
        self.http_error_msg.textChanged.connect(self.update_preview)
        
        self.http_container.hide() 
        # --------------------------------------------

        wl_h = QHBoxLayout()
        self.btn_wl = QPushButton("Wordlist Seç"); self.btn_wl.clicked.connect(self.select_pass_wl)
        self.wl_label = QLabel("Seçilmedi"); wl_h.addWidget(self.btn_wl); wl_h.addWidget(self.wl_label)

        self.threads_input = QLineEdit(); self.threads_input.setPlaceholderText("Hız / Thread (Örn: 4)")
        self.threads_input.textChanged.connect(self.update_preview)
        
        btn_h = QHBoxLayout()
        self.run_btn = QPushButton("Saldırıyı Başlat"); self.run_btn.setStyleSheet("background-color: #ff3333; color: white; font-weight: bold;")
        self.run_btn.clicked.connect(self.start_brute)
        self.stop_btn = QPushButton("Durdur"); self.stop_btn.setEnabled(False); self.stop_btn.clicked.connect(self.stop_brute)
        btn_h.addWidget(self.run_btn); btn_h.addWidget(self.stop_btn)

        left_layout.addWidget(title)
        left_layout.addWidget(QLabel("Hedef IP / URL:")); left_layout.addWidget(self.target_input)
        left_layout.addWidget(QLabel("Servis:")); left_layout.addWidget(self.service_combo)
        left_layout.addWidget(self.http_container) 
        left_layout.addWidget(QLabel("Kullanıcı:")); left_layout.addWidget(self.user_input)
        left_layout.addLayout(wl_h)
        left_layout.addWidget(QLabel("Thread:")); left_layout.addWidget(self.threads_input)
        left_layout.addLayout(btn_h); left_layout.addStretch()

        # ================= SAĞ TARAF =================
        right_container = QVBoxLayout(); right_container.setSpacing(15)
        self.top_preview_panel = ModernPanel(); top_preview_layout = QVBoxLayout(self.top_preview_panel)
        top_preview_layout.addWidget(QLabel("Canlı Komut Önizleme (Otomatik Oluşturulur):", styleSheet="color: #00ffcc; font-weight: bold;"))
        self.preview = QTextEdit(); self.preview.setMaximumHeight(55); self.preview.setReadOnly(False)
        self.preview.setStyleSheet("background-color: rgba(0,0,0,120); border: 1px solid #333; color: #00ff00;")
        top_preview_layout.addWidget(self.preview)

        self.bottom_terminal_panel = ModernPanel(); bottom_terminal_layout = QVBoxLayout(self.bottom_terminal_panel)
        bottom_terminal_layout.addWidget(QLabel("Saldırı Logları / Çıktı:", styleSheet="color: #ff3333; font-weight: bold;"))
        self.terminal = QTextEdit(); self.terminal.setReadOnly(True)
        self.terminal.setStyleSheet("background-color: rgba(0,0,0,150); color: #00ff00; font-family: 'Courier New';")
        bottom_terminal_layout.addWidget(self.terminal)

        right_container.addWidget(self.top_preview_panel, 1); right_container.addWidget(self.bottom_terminal_panel, 6)
        main_layout.addWidget(left_panel); main_layout.addLayout(right_container, 3)

        self.tray_icon = QSystemTrayIcon(self); self.tray_icon.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)); self.tray_icon.show()
        self.update_preview()

    def toggle_http_fields(self, text):
        if "http" in text: self.http_container.show()
        else: self.http_container.hide()

    def select_pass_wl(self):
        f, _ = QFileDialog.getOpenFileName(self, "Şifre Listesi Seç", "", "Text Files (*.txt);;All Files (*)", options=QFileDialog.Option.DontUseNativeDialog)
        if f: 
            self.pass_path = f; self.wl_label.setText(os.path.basename(f)); self.update_preview()

    def update_preview(self):
        target = self.target_input.text().strip() or "IP"
        user = self.user_input.text().strip() or "USER"
        service = self.service_combo.currentText()
        wl = self.pass_path if self.pass_path else "WORDLIST"
        
        if "http" in service:
            path = self.http_path.text().strip() or "/login.php"
            data = self.http_post_data.text().strip() or "user=^USER^&pass=^PASS^"
            error = self.http_error_msg.text().strip() or "Hata"
            extra = f'"{path}:{data}:F={error}"'
            cmd = f"hydra -l {user} -P {wl} {target} {service} {extra}"
        else:
            cmd = f"hydra -l {user} -P {wl} {target} {service}"
            
        if self.threads_input.text().strip(): cmd += f" -t {self.threads_input.text()}"
        self.preview.setPlainText(cmd)

    def start_brute(self):
        raw_cmd = self.preview.toPlainText().strip()
        if not raw_cmd or "WORDLIST" in raw_cmd: return
        try: cmd = shlex.split(raw_cmd)
        except: cmd = raw_cmd.split()
        self.terminal.clear(); self.run_btn.setEnabled(False); self.stop_btn.setEnabled(True)
        self.brute_thread = ScannerThread(cmd); self.brute_thread.output_signal.connect(lambda t: self.terminal.insertPlainText(t))
        self.brute_thread.finished_signal.connect(self.on_finished); self.brute_thread.start()

    def on_finished(self, out):
        self.run_btn.setEnabled(True); self.stop_btn.setEnabled(False)
        self.tray_icon.showMessage("🔥 Brute Force", "İşlem tamamlandı!", QSystemTrayIcon.MessageIcon.Information, 3000)

    def stop_brute(self):
        if self.brute_thread: self.brute_thread.stop()