import re
import json
import urllib.request
import urllib.parse
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
                             QPushButton, QTextEdit, QTableWidget, QTableWidgetItem,
                             QHeaderView, QComboBox, QTabWidget, QSystemTrayIcon, QStyle,
                             QProgressBar, QMenu, QFileDialog)
from PyQt6.QtGui import QBrush, QColor
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from ui_components import ModernPanel


# ─────────────────────────────────────────────
#  ARKA PLAN API İŞ PARÇACIĞI
# ─────────────────────────────────────────────
class CVEFetchThread(QThread):
    result_signal  = pyqtSignal(list)   # CVE listesi
    error_signal   = pyqtSignal(str)    # Hata mesajı
    status_signal  = pyqtSignal(str)    # Durum mesajı

    def __init__(self, keyword, severity_filter="ALL"):
        super().__init__()
        self.keyword         = keyword
        self.severity_filter = severity_filter

    def run(self):
        self.status_signal.emit(f"'{self.keyword}' için NVD API'ye sorgu gönderiliyor...")
        try:
            encoded  = urllib.parse.quote(self.keyword)
            url      = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded}&resultsPerPage=50"
            req      = urllib.request.Request(url, headers={"User-Agent": "SOC-Toolkit/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())

            cves = []
            for item in data.get("vulnerabilities", []):
                cve   = item.get("cve", {})
                cve_id = cve.get("id", "N/A")

                # Açıklama (İngilizce)
                desc = next(
                    (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                    "Açıklama bulunamadı."
                )

                # CVSS Skoru + Severity
                score    = "N/A"
                severity = "N/A"
                metrics  = cve.get("metrics", {})
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics and metrics[key]:
                        cvss_data = metrics[key][0].get("cvssData", {})
                        score     = str(cvss_data.get("baseScore", "N/A"))
                        severity  = metrics[key][0].get("baseSeverity",
                                      cvss_data.get("baseSeverity", "N/A"))
                        break

                # Yayın Tarihi
                published = cve.get("published", "")[:10]

                # Severity filtresi
                if self.severity_filter != "ALL" and severity.upper() != self.severity_filter:
                    continue

                cves.append({
                    "id":        cve_id,
                    "score":     score,
                    "severity":  severity.upper(),
                    "published": published,
                    "desc":      desc
                })

            self.status_signal.emit(f"{len(cves)} CVE bulundu.")
            self.result_signal.emit(cves)

        except urllib.error.URLError as e:
            self.error_signal.emit(f"Bağlantı Hatası: {str(e)}\nİnternet bağlantınızı kontrol edin.")
        except Exception as e:
            self.error_signal.emit(f"Beklenmeyen Hata: {str(e)}")


# ─────────────────────────────────────────────
#  ANA SEKME
# ─────────────────────────────────────────────
class CVETab(QWidget):
    def __init__(self):
        super().__init__()
        self.fetch_thread = None
        self.all_cves     = []
        self.init_ui()

    # ── UI KURULUM ──────────────────────────────
    def init_ui(self):
        main_layout = QHBoxLayout(self)
        main_layout.setSpacing(15)

        # ── SOL PANEL ──────────────────────────
        left_panel = ModernPanel()
        left_panel.setFixedWidth(330)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setSpacing(12)

        title = QLabel("CVE Zafiyet Araştırma")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: white;")
        left_layout.addWidget(title)

        desc = QLabel("NVD API kullanır · Ücretsiz · Key gerekmez")
        desc.setStyleSheet("color: #888; font-size: 11px;")
        left_layout.addWidget(desc)

        # Arama kutusu
        left_layout.addWidget(QLabel("Servis / Anahtar Kelime:",
                                     styleSheet="color:#00ffcc; font-weight:bold;"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Örn: apache, openssh, windows smb")
        self.search_input.returnPressed.connect(self.start_search)
        left_layout.addWidget(self.search_input)

        # Severity filtresi
        left_layout.addWidget(QLabel("Severity Filtresi:",
                                     styleSheet="color:#00ffcc; font-weight:bold;"))
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        left_layout.addWidget(self.severity_combo)

        # Hızlı arama butonları
        left_layout.addWidget(QLabel("Hızlı Aramalar:",
                                     styleSheet="color:#ffaa00; font-size:11px;"))
        quick_terms = ["apache", "openssh", "windows smb", "log4j", "wordpress", "nginx"]
        for term in quick_terms:
            btn = QPushButton(f"  {term}")
            btn.setStyleSheet("""
                QPushButton {
                    background: rgba(0,150,255,60);
                    border: 1px solid rgba(0,150,255,120);
                    border-radius: 4px;
                    padding: 6px;
                    text-align: left;
                    color: #aaddff;
                    font-size: 12px;
                }
                QPushButton:hover { background: rgba(0,150,255,120); color: white; }
            """)
            btn.clicked.connect(lambda _, t=term: self._quick_search(t))
            left_layout.addWidget(btn)

        # Ara butonu
        self.run_btn = QPushButton("🔍  Ara")
        self.run_btn.setStyleSheet(
            "background-color: #ff3333; color: white; font-weight: bold; padding: 10px;")
        self.run_btn.clicked.connect(self.start_search)
        left_layout.addWidget(self.run_btn)

        # Dışa aktar
        self.export_btn = QPushButton("💾  JSON Olarak Kaydet")
        self.export_btn.setStyleSheet(
            "background-color: rgba(0,200,100,160); color: white; font-weight: bold; padding: 8px;")
        self.export_btn.clicked.connect(self.export_json)
        self.export_btn.setEnabled(False)
        left_layout.addWidget(self.export_btn)

        left_layout.addStretch()

        # İstatistik kutusu
        self.stats_box = ModernPanel()
        stats_layout = QVBoxLayout(self.stats_box)
        self.stats_label = QLabel("─ Sonuç Bekleniyor ─")
        self.stats_label.setStyleSheet("color: #888; font-size: 12px;")
        self.stats_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        stats_layout.addWidget(self.stats_label)
        left_layout.addWidget(self.stats_box)

        # ── SAĞ TARAF ──────────────────────────
        right_container = QVBoxLayout()
        right_container.setSpacing(15)

        # Durum çubuğu
        status_panel = ModernPanel()
        status_layout = QHBoxLayout(status_panel)
        self.status_label = QLabel("Hazır. Bir servis adı girerek arama yapın.")
        self.status_label.setStyleSheet("color: #00ffcc; font-size: 12px;")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)   # belirsiz mod
        self.progress_bar.setMaximumWidth(120)
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet(
            "QProgressBar { border: 1px solid #333; border-radius: 4px; background: #111; }"
            "QProgressBar::chunk { background: #00ffcc; }")
        status_layout.addWidget(self.status_label, 1)
        status_layout.addWidget(self.progress_bar)

        # Sonuç tablosu
        table_panel = ModernPanel()
        table_layout = QVBoxLayout(table_panel)
        table_layout.addWidget(QLabel("Bulunan CVE'ler:",
                                      styleSheet="color: #ff3333; font-weight: bold;"))

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["CVE ID", "Skor", "Severity", "Tarih", "Açıklama"])
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.table.itemSelectionChanged.connect(self.show_detail)
        self.table.setColumnWidth(0, 150)
        self.table.setColumnWidth(1, 60)
        self.table.setColumnWidth(2, 90)
        self.table.setColumnWidth(3, 90)
        table_layout.addWidget(self.table)

        # Detay paneli
        detail_panel = ModernPanel()
        detail_layout = QVBoxLayout(detail_panel)
        detail_layout.addWidget(QLabel("CVE Detayı:",
                                       styleSheet="color: #ffaa00; font-weight: bold;"))
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setMaximumHeight(120)
        self.detail_text.setStyleSheet(
            "background: rgba(0,0,0,150); color: #e0e0e0; font-size: 12px;"
            "border: 1px solid #333;")
        detail_layout.addWidget(self.detail_text)

        right_container.addWidget(status_panel, 0)
        right_container.addWidget(table_panel, 5)
        right_container.addWidget(detail_panel, 2)

        main_layout.addWidget(left_panel)
        main_layout.addLayout(right_container, 3)

        # Bildirim
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))
        self.tray_icon.show()
        

    # ── ARAMA ───────────────────────────────────
    def _quick_search(self, term):
        self.search_input.setText(term)
        self.start_search()

    def start_search(self):
        keyword = self.search_input.text().strip()
        if not keyword:
            self.status_label.setText("⚠️  Lütfen bir anahtar kelime girin.")
            return

        self.run_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.table.setRowCount(0)
        self.detail_text.clear()
        self.export_btn.setEnabled(False)
        self.all_cves = []

        severity = self.severity_combo.currentText()
        self.fetch_thread = CVEFetchThread(keyword, severity)
        self.fetch_thread.result_signal.connect(self.populate_table)
        self.fetch_thread.error_signal.connect(self.show_error)
        self.fetch_thread.status_signal.connect(lambda s: self.status_label.setText(s))
        self.fetch_thread.start()

    # ── TABLO DOLDURMA ──────────────────────────
    def populate_table(self, cves):
        self.run_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.all_cves = cves

        if not cves:
            self.status_label.setText("Sonuç bulunamadı.")
            return

        # İstatistikler
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "N/A": 0}
        for c in cves:
            sev = c["severity"]
            counts[sev] = counts.get(sev, 0) + 1

        self.stats_label.setText(
            f"Toplam: {len(cves)}\n"
            f"🔴 Critical: {counts.get('CRITICAL',0)}  "
            f"🟠 High: {counts.get('HIGH',0)}\n"
            f"🟡 Medium: {counts.get('MEDIUM',0)}  "
            f"🟢 Low: {counts.get('LOW',0)}"
        )
        self.stats_label.setStyleSheet("color: #e0e0e0; font-size: 12px;")

        # Satırları ekle
        for cve in cves:
            r = self.table.rowCount()
            self.table.insertRow(r)

            id_item   = QTableWidgetItem(cve["id"])
            sco_item  = QTableWidgetItem(cve["score"])
            sev_item  = QTableWidgetItem(cve["severity"])
            pub_item  = QTableWidgetItem(cve["published"])
            desc_item = QTableWidgetItem(cve["desc"][:120] + "…"
                                         if len(cve["desc"]) > 120 else cve["desc"])

            # Severity rengi
            color_map = {
                "CRITICAL": QColor(255, 50,  50),
                "HIGH":     QColor(255, 140,  0),
                "MEDIUM":   QColor(255, 215,  0),
                "LOW":      QColor(100, 220, 100),
            }
            col = color_map.get(cve["severity"], QColor(180, 180, 180))
            sev_item.setForeground(QBrush(col))
            sco_item.setForeground(QBrush(col))
            id_item.setForeground(QBrush(QColor(0, 200, 255)))

            self.table.setItem(r, 0, id_item)
            self.table.setItem(r, 1, sco_item)
            self.table.setItem(r, 2, sev_item)
            self.table.setItem(r, 3, pub_item)
            self.table.setItem(r, 4, desc_item)

        self.export_btn.setEnabled(True)
        self.tray_icon.showMessage(
            "🛡️ CVE Araştırma",
            f"{len(cves)} zafiyet bulundu: {self.search_input.text()}",
            QSystemTrayIcon.MessageIcon.Warning, 4000
        )

    # ── DETAY PANELİ ────────────────────────────
    def show_detail(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        r = rows[0].row()
        if r < len(self.all_cves):
            cve = self.all_cves[r]
            self.detail_text.setHtml(
                f"<b style='color:#00ffcc'>{cve['id']}</b>  "
                f"<span style='color:#ffaa00'>Skor: {cve['score']} | {cve['severity']}</span>"
                f"  <span style='color:#888'>({cve['published']})</span><br><br>"
                f"<span style='color:#e0e0e0'>{cve['desc']}</span><br><br>"
                f"<a style='color:#4488ff' href='https://nvd.nist.gov/vuln/detail/{cve['id']}'>"
                f"→ NVD Sayfasını Aç</a>"
            )

    # ── SAĞ TIK MENÜ ────────────────────────────
    def show_context_menu(self, pos):
        item = self.table.itemAt(pos)
        if not item:
            return
        cve_id = self.table.item(item.row(), 0).text()
        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background:#2a2a35; color:white; border:1px solid #555; }"
                           "QMenu::item:selected { background:#0078d4; }")
        act_nvd    = menu.addAction(f"🌐 NVD'de Aç: {cve_id}")
        act_copy   = menu.addAction("📋 CVE ID Kopyala")
        action = menu.exec(self.table.mapToGlobal(pos))
        if action == act_nvd:
            import webbrowser
            webbrowser.open(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
        elif action == act_copy:
            from PyQt6.QtWidgets import QApplication
            QApplication.clipboard().setText(cve_id)

    # ── HATA ────────────────────────────────────
    def show_error(self, msg):
        self.run_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"❌ {msg}")
        self.detail_text.setHtml(
            f"<span style='color:#ff4444'>{msg}</span>")

    # ── JSON KAYIT ───────────────────────────────
    def export_json(self):
        f, _ = QFileDialog.getSaveFileName(
            self, "CVE Verilerini Kaydet", "",
            "JSON Files (*.json)",
            options=QFileDialog.Option.DontUseNativeDialog
        )
        if f:
            with open(f, "w", encoding="utf-8") as jf:
                json.dump({
                    "keyword": self.search_input.text(),
                    "total":   len(self.all_cves),
                    "cves":    self.all_cves
                }, jf, indent=4, ensure_ascii=False)
            self.status_label.setText(f"✅ Kaydedildi: {f}")
    # ── KANKA: NMAP'TEN GELEN ARAMAYI TETİKLEYEN FONKSİYON ──
    def external_search(self, keyword):
        self.search_input.setText(keyword)
        self.start_search()