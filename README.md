# 🦉 OHive

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Forensics%20/%20DFIR-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OHive** — Windows registry hive parser (regf) — key tree, value decode, ATT&CK persistence (offline) ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OHive is an offline-first OwlSec tool for Windows registry hive parser (regf) — key tree, value decode, ATT&CK persistence (offline). It provides an interactive cyan terminal UI and a full CLI with multi-format export (TXT, Markdown, JSON, CSV, SARIF), designed for authorized security work on Linux.

---

## ✨ Features

- Parse Windows registry hives (regf) fully offline
- Walk key trees and decode common value types
- Highlight ATT&CK-relevant persistence locations
- Dump and path-focused inspection modes
- Interactive exploration plus CLI automation
- Export findings to standard report formats

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OHive OHive.go
./OHive --help
./OHive --input SOFTWARE --tree
./OHive --input SYSTEM --path ControlSet001\\Services --format json
./OHive --list-attck
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad
