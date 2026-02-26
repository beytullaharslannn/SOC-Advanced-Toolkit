import subprocess
from PyQt6.QtCore import QThread, pyqtSignal

class ScannerThread(QThread):
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(str)

    def __init__(self, cmd):
        super().__init__()
        self.cmd = cmd
        self.full_output = ""
        self.process = None
        self.is_cancelled = False

    def run(self):
        try:
            self.process = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, shell=False)
            for line in self.process.stdout:
                if self.is_cancelled: break
                self.full_output += line
                self.output_signal.emit(line)
            self.process.wait()
            if self.is_cancelled:
                self.output_signal.emit("\n[!] İşlem kullanıcı tarafından durduruldu.\n")
                self.finished_signal.emit("")
            else:
                self.output_signal.emit("\n[+] İşlem tamamlandı.\n")
                self.finished_signal.emit(self.full_output)
        except FileNotFoundError:
            self.output_signal.emit("\n[-] HATA: Araç (nmap/gobuster vb.) sistemde bulunamadı. Lütfen yüklü olduğundan ve PATH'e eklendiğinden emin ol.\n")
            self.finished_signal.emit("")
        except Exception as e:
            self.output_signal.emit(f"\n[-] Beklenmeyen Hata: {str(e)}\n")
            self.finished_signal.emit("")

    def stop(self):
        self.is_cancelled = True
        if self.process: self.process.terminate()