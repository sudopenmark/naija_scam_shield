"""
ui/screens/qr_screen.py - QR Code / Barcode Scanner Screen
Author: Joshua Akadri
"""

import logging
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QFileDialog, QLineEdit
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QImage, QPixmap
from core.config import AppConfig

logger = logging.getLogger(__name__)

try:
    import cv2
    import numpy as np
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

try:
    from pyzbar import pyzbar
    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False

try:
    from PIL import Image
    from pyzbar.pyzbar import decode as pyzbar_decode
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


class CameraWorker(QThread):
    """Background camera capture thread."""
    frame_ready = pyqtSignal(object)  # numpy array
    url_found = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, camera_index: int = 0):
        super().__init__()
        self.camera_index = camera_index
        self._running = False

    def run(self):
        if not CV2_AVAILABLE or not PYZBAR_AVAILABLE:
            self.error.emit("Camera/QR libraries not available. Install opencv-python and pyzbar.")
            return

        cap = cv2.VideoCapture(self.camera_index)
        if not cap.isOpened():
            self.error.emit("Could not open camera. Check permissions or camera index.")
            return

        self._running = True
        found_urls = set()

        while self._running:
            ret, frame = cap.read()
            if not ret:
                break

            self.frame_ready.emit(frame.copy())

            decoded = pyzbar.decode(frame)
            for obj in decoded:
                data = obj.data.decode("utf-8", errors="ignore")
                if data not in found_urls:
                    found_urls.add(data)
                    if data.startswith(("http://", "https://")) or "." in data:
                        self.url_found.emit(data)
                        self._running = False
                        break

        cap.release()

    def stop(self):
        self._running = False


class QRScannerScreen(QWidget):
    """QR Code and barcode scanner screen."""

    url_detected = pyqtSignal(str)  # emitted when a URL is found

    def __init__(self, config: AppConfig):
        super().__init__()
        self.config = config
        self._worker = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(16)

        title = QLabel("QR Code Scanner")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        subtitle = QLabel("Scan a QR code from your camera or image file")
        subtitle.setFont(QFont("Segoe UI", 11))
        subtitle.setStyleSheet("color: #64748b;")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        # Camera view
        self._camera_frame = QFrame()
        self._camera_frame.setMinimumHeight(360)
        self._camera_frame.setStyleSheet(
            "QFrame { background-color: #0f1117; border: 2px dashed #2a2d3e; "
            "border-radius: 12px; }"
        )
        cam_layout = QVBoxLayout(self._camera_frame)
        cam_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._camera_label = QLabel()
        self._camera_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._camera_label.setMinimumSize(640, 360)

        self._placeholder_label = QLabel("📷\nCamera feed will appear here\nwhen scanning is active")
        self._placeholder_label.setFont(QFont("Segoe UI Emoji", 14))
        self._placeholder_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._placeholder_label.setStyleSheet("color: #475569;")

        cam_layout.addWidget(self._camera_label)
        cam_layout.addWidget(self._placeholder_label)
        layout.addWidget(self._camera_frame, 1)

        # Status
        self._status_lbl = QLabel("Camera not active")
        self._status_lbl.setFont(QFont("Segoe UI", 10))
        self._status_lbl.setStyleSheet("color: #64748b;")
        self._status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._status_lbl)

        # Controls
        controls = QHBoxLayout()
        controls.setSpacing(10)

        self._start_btn = QPushButton("▶ Start Camera Scan")
        self._start_btn.setFixedHeight(42)
        self._start_btn.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self._start_btn.clicked.connect(self._start_camera)

        self._stop_btn = QPushButton("⏹ Stop")
        self._stop_btn.setFixedHeight(42)
        self._stop_btn.setProperty("class", "secondary")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_camera)

        file_btn = QPushButton("🖼 Scan from Image File")
        file_btn.setFixedHeight(42)
        file_btn.setProperty("class", "secondary")
        file_btn.clicked.connect(self._scan_file)

        controls.addWidget(self._start_btn, 1)
        controls.addWidget(self._stop_btn)
        controls.addWidget(file_btn)
        layout.addLayout(controls)

        # Manual URL box (shows detected URL)
        self._detected_url = QLineEdit()
        self._detected_url.setPlaceholderText("Detected URL will appear here…")
        self._detected_url.setFixedHeight(40)
        self._detected_url.setReadOnly(True)
        layout.addWidget(self._detected_url)

        scan_detected_btn = QPushButton("🔍 Scan Detected URL")
        scan_detected_btn.setFixedHeight(42)
        scan_detected_btn.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        scan_detected_btn.clicked.connect(self._scan_detected_url)
        layout.addWidget(scan_detected_btn)

        if not CV2_AVAILABLE or not PYZBAR_AVAILABLE:
            warn = QLabel(
                "⚠️ Camera scanning requires: pip install opencv-python pyzbar\n"
                "You can still scan from image files using Pillow: pip install Pillow pyzbar"
            )
            warn.setStyleSheet("color: #f59e0b; font-size: 11px;")
            warn.setWordWrap(True)
            layout.addWidget(warn)

    def _start_camera(self):
        if not CV2_AVAILABLE or not PYZBAR_AVAILABLE:
            self._status_lbl.setText("⚠️ Camera libraries not installed. See warning above.")
            return

        self._worker = CameraWorker(0)
        self._worker.frame_ready.connect(self._update_frame)
        self._worker.url_found.connect(self._on_url_found)
        self._worker.error.connect(self._on_error)
        self._worker.start()

        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._status_lbl.setText("🟢 Scanning… Point camera at a QR code")

    def _stop_camera(self):
        if self._worker:
            self._worker.stop()
            self._worker = None
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._status_lbl.setText("Camera stopped")
        self._camera_label.clear()
        self._placeholder_label.setVisible(True)

    def _update_frame(self, frame):
        if not CV2_AVAILABLE:
            return
        import cv2
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        h, w, c = rgb.shape
        qimg = QImage(rgb.data, w, h, w * c, QImage.Format.Format_RGB888)
        pixmap = QPixmap.fromImage(qimg).scaled(
            640, 360, Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation
        )
        self._camera_label.setPixmap(pixmap)
        self._placeholder_label.setVisible(False)

    def _on_url_found(self, url: str):
        self._stop_camera()
        self._detected_url.setText(url)
        self._status_lbl.setText(f"✅ URL detected: {url}")

    def _on_error(self, error: str):
        self._status_lbl.setText(f"⚠️ {error}")
        self._stop_camera()

    def _scan_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Image with QR Code", "",
            "Images (*.png *.jpg *.jpeg *.bmp *.gif *.webp)"
        )
        if not path:
            return

        try:
            if PIL_AVAILABLE:
                from PIL import Image
                from pyzbar.pyzbar import decode
                img = Image.open(path)
                decoded = decode(img)
                if decoded:
                    url = decoded[0].data.decode("utf-8")
                    self._detected_url.setText(url)
                    self._status_lbl.setText(f"✅ URL found in image: {url}")
                else:
                    self._status_lbl.setText("⚠️ No QR code found in image")
            elif CV2_AVAILABLE and PYZBAR_AVAILABLE:
                import cv2
                from pyzbar import pyzbar
                img = cv2.imread(path)
                decoded = pyzbar.decode(img)
                if decoded:
                    url = decoded[0].data.decode("utf-8")
                    self._detected_url.setText(url)
                    self._status_lbl.setText(f"✅ URL found in image: {url}")
                else:
                    self._status_lbl.setText("⚠️ No QR code found in image")
            else:
                self._status_lbl.setText("⚠️ QR image scanning requires Pillow and pyzbar")
        except Exception as e:
            self._status_lbl.setText(f"⚠️ Error reading image: {e}")

    def _scan_detected_url(self):
        url = self._detected_url.text().strip()
        if url:
            self.url_detected.emit(url)
