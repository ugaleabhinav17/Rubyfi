"""
gui/styles.py  —  RubyFi Elite Cyberpunk Theme v2
Inspired by: Kali NetHunter, Metasploit Pro, NSA/GCHQ tooling aesthetics.
Palette:
  bg-deep    #05080f   (near-black navy)
  bg-mid     #0a0f1a   (panels)
  bg-card    #0f1724   (cards / table rows)
  border     #1a2640   (subtle borders)
  accent-1   #00d4ff   (cyan  — primary actions)
  accent-2   #ff0040   (red   — danger / attack)
  accent-3   #00ff88   (green — success / monitor)
  accent-4   #ffb700   (amber — handshake / warning)
  accent-5   #9b5de5   (violet — evil-twin / special)
  text-hi    #e8f4fd   (high-contrast body text)
  text-mid   #7a9bbf   (secondary labels)
  text-dim   #3d5a7a   (disabled / placeholder)
"""

DARK_THEME = """

/* ═══════════════ BASE WINDOW ═══════════════ */
QMainWindow, QDialog {
    background: #05080f;
    color: #e8f4fd;
}

QWidget {
    background: transparent;
    color: #e8f4fd;
    font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
    font-size: 12px;
}

/* ═══════════════ SCROLLBARS ═══════════════ */
QScrollBar:vertical {
    background: #0a0f1a;
    width: 8px;
    border: none;
    border-radius: 4px;
}
QScrollBar::handle:vertical {
    background: #1a2640;
    border-radius: 4px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover { background: #00d4ff; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

QScrollBar:horizontal {
    background: #0a0f1a;
    height: 8px;
    border: none;
    border-radius: 4px;
}
QScrollBar::handle:horizontal {
    background: #1a2640;
    border-radius: 4px;
    min-width: 20px;
}
QScrollBar::handle:horizontal:hover { background: #00d4ff; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

/* ═══════════════ BUTTONS ═══════════════ */
QPushButton {
    background: #0a0f1a;
    border: 1px solid #1a2640;
    border-radius: 6px;
    padding: 8px 18px;
    color: #7a9bbf;
    font-weight: bold;
    font-size: 12px;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
}
QPushButton:hover {
    border-color: #00d4ff;
    color: #00d4ff;
    background: #0f1e2e;
}
QPushButton:pressed {
    background: #0a1520;
    border-color: #00a8cc;
    color: #00a8cc;
}
QPushButton:disabled {
    background: #070b12;
    border-color: #111b27;
    color: #2a3d52;
}

/* ═══════════════ TABLE ═══════════════ */
QTableWidget {
    background: #05080f;
    border: 1px solid #1a2640;
    border-radius: 0px;
    color: #e8f4fd;
    gridline-color: #0f1724;
    selection-background-color: transparent;
    outline: none;
    font-size: 12px;
}
QTableWidget::item {
    padding: 6px 10px;
    border-bottom: 1px solid #0f1724;
    background: transparent;
}
QTableWidget::item:selected {
    background: #0d1e35;
    border-left: 3px solid #00d4ff;
    color: #00d4ff;
}
QTableWidget::item:hover {
    background: #0a1520;
}
QHeaderView::section {
    background: #080d16;
    color: #3d5a7a;
    padding: 8px 10px;
    border: none;
    border-bottom: 1px solid #1a2640;
    border-right: 1px solid #0f1724;
    font-weight: bold;
    font-size: 10px;
    letter-spacing: 2px;
    text-transform: uppercase;
}
QHeaderView::section:first { border-left: none; }

/* ═══════════════ PROGRESS BAR ═══════════════ */
QProgressBar {
    border: 1px solid #1a2640;
    border-radius: 3px;
    background: #080d16;
    text-align: center;
    color: #7a9bbf;
    font-weight: bold;
    font-size: 11px;
    height: 18px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #00d4ff, stop:0.5 #0099cc, stop:1 #00d4ff);
    border-radius: 2px;
}

/* ═══════════════ TEXT / LOG ═══════════════ */
QTextEdit {
    background: #030608;
    border: 1px solid #1a2640;
    border-radius: 0px;
    color: #00d4ff;
    font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
    font-size: 11px;
    padding: 8px;
    selection-background-color: #0d2a40;
}

/* ═══════════════ LABELS ═══════════════ */
QLabel {
    color: #7a9bbf;
    font-size: 12px;
    background: transparent;
}

/* ═══════════════ STATUS BAR ═══════════════ */
QStatusBar {
    background: #030608;
    color: #3d5a7a;
    border-top: 1px solid #1a2640;
    font-size: 10px;
    font-family: 'JetBrains Mono', monospace;
}
QStatusBar::item { border: none; }

/* ═══════════════ SPLITTER ═══════════════ */
QSplitter::handle {
    background: #1a2640;
}
QSplitter::handle:hover {
    background: #00d4ff;
}

/* ═══════════════ TOOLTIPS ═══════════════ */
QToolTip {
    background: #0a0f1a;
    border: 1px solid #00d4ff;
    color: #e8f4fd;
    padding: 5px 8px;
    border-radius: 4px;
    font-size: 11px;
}

/* ═══════════════ COMBO BOX ═══════════════ */
QComboBox {
    background: #0a0f1a;
    border: 1px solid #1a2640;
    border-radius: 4px;
    padding: 6px 12px;
    color: #7a9bbf;
    font-size: 12px;
}
QComboBox:hover { border-color: #00d4ff; color: #00d4ff; }
QComboBox::drop-down { border: none; width: 20px; }
QComboBox QAbstractItemView {
    background: #0a0f1a;
    border: 1px solid #1a2640;
    color: #e8f4fd;
    selection-background-color: #0d1e35;
}

/* ═══════════════ LINE EDIT ═══════════════ */
QLineEdit {
    background: #0a0f1a;
    border: 1px solid #1a2640;
    border-radius: 4px;
    padding: 6px 10px;
    color: #e8f4fd;
    font-size: 12px;
}
QLineEdit:focus { border-color: #00d4ff; }

/* ═══════════════ GROUP BOX ═══════════════ */
QGroupBox {
    border: 1px solid #1a2640;
    border-radius: 6px;
    margin-top: 12px;
    padding-top: 12px;
    color: #3d5a7a;
    font-size: 10px;
    letter-spacing: 2px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
    color: #3d5a7a;
}

/* ═══════════════ MESSAGE BOX ═══════════════ */
QMessageBox {
    background: #0a0f1a;
    color: #e8f4fd;
}
QMessageBox QPushButton {
    min-width: 80px;
    padding: 6px 16px;
}
"""
