from PyQt6.QtWidgets import QWidget, QFrame
from PyQt6.QtGui import QPainter, QColor, QRadialGradient, QBrush
from PyQt6.QtCore import QTimer, Qt, QPointF

class AnimatedBackground(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.orbs = [
            {'x': 100, 'y': 100, 'dx': 1.2, 'dy': 0.8, 'radius': 450, 'color': QColor(0, 255, 255, 35)},
            {'x': 500, 'y': 300, 'dx': -1.0, 'dy': 1.2, 'radius': 550, 'color': QColor(138, 43, 226, 35)},
            {'x': 800, 'y': 600, 'dx': 0.8, 'dy': -1.0, 'radius': 500, 'color': QColor(255, 20, 147, 25)}
        ]
        self.timer = QTimer(self); self.timer.timeout.connect(self.update_animation); self.timer.start(16)

    def update_animation(self):
        w, h = self.width(), self.height()
        for orb in self.orbs:
            orb['x'] += orb['dx']; orb['y'] += orb['dy']
            if orb['x'] <= 0 or orb['x'] >= w: orb['dx'] *= -1
            if orb['y'] <= 0 or orb['y'] >= h: orb['dy'] *= -1
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self); painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor(10, 10, 15))
        painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Screen)
        for orb in self.orbs:
            gradient = QRadialGradient(QPointF(orb['x'], orb['y']), orb['radius'])
            gradient.setColorAt(0, orb['color']); gradient.setColorAt(1, QColor(0, 0, 0, 0))
            painter.setBrush(QBrush(gradient)); painter.setPen(Qt.PenStyle.NoPen); painter.drawRect(self.rect())

class ModernPanel(QFrame):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("QFrame { background-color: rgba(25, 25, 30, 195); border-radius: 12px; border: 1px solid rgba(255, 255, 255, 25); }")