# M-Kavach Lite 🛡️

A Tkinter-based Cybersecurity Scanner Dashboard designed to detect mobile malware and fraud risks by interfacing with Android devices via ADB or using a built-in simulation dataset[cite: 1].

## Features
- **ADB Integration:** Connects to real Android devices via USB debugging to list sideloaded apps and check installer sources[cite: 1].
- **Simulation Mode:** Falls back to a robust demo dataset for seamless presentations when no device is attached[cite: 1].
- **Risk Classification:** Automatically flags HIGH, MEDIUM, and LOW risk applications based on heuristic analysis[cite: 1].
- **Pure Python:** Built entirely using Python standard libraries (`tkinter`, `subprocess`, `threading`, etc.) with zero third-party package dependencies[cite: 1].

## Requirements
- Python 3.x
- Optional: Android Debug Bridge (`adb`) installed on your system path[cite: 1].

## How to Run
```bash
python mkavach_lite.py
