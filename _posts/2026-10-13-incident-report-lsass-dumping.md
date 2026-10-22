---
title: "Báo cáo điều tra sự cố: LSASS Dumping (T1003.001)"
date: 2026-10-13 22:50:00 +0700
categories: [DFIR, Incident Report]
tags: [soc, wazuh, sysmon, mitre-attack, t1003, lsass, atomic-red-team]
---

# BÁO CÁO ĐIỀU TRA SỰ CỐ BẢO MẬT (INCIDENT INVESTIGATION REPORT)

## THÔNG TIN TỔNG QUAN (INCIDENT OVERVIEW)

* **Mã sự cố (Ticket ID):** `INC-20261013-004`
* **Người thực hiện điều tra:** SOC L1 Analyst (`curlam`)
* **Thời gian ghi nhận (Detected Time):** 2026-10-13 22:50:00 (UTC+7)
* **Mức độ nghiêm trọng (Severity):** High / Critical (Wazuh Level 12)
* **Trạng thái (Status):** Đã đóng - True Positive (Authorized Emulation / Lab Simulation)
* **Phân loại tấn công (Attack Category):** Credential Access / LSASS Dumping

---

## 1. ĐỐI TƯỢNG VÀ PHẠM VI ẢNH HƯỞNG (SCOPE & ASSET)

| Trường thông tin | Dữ liệu chi tiết |
| :--- | :--- |
| **Thiết bị ảnh hưởng (Hostname)** | `Victim-Pentium-Win10` (Agent ID: `004`) |
| **Địa chỉ IP nội bộ** | `192.168.100.17` |
| **Tài khoản thực thi (User Account)** | `DESKTOP-R7VHEE7\curlam` (Integrity Level: High) |
| **Hệ thống phát hiện (Detection Source)** | Wazuh SIEM + Sysmon Telemetry (Event ID 1 / EID 10) |
| **Quy tắc kích hoạt (Triggered Rule)** | Rule ID `100610` / `100611` |

---

## 2. ÁNH XẠ KHUNG TẤN CÔNG (MITRE ATT&CK MAPPING)

* **Chiến thuật (Tactic):** [TA0006 - Credential Access](https://attack.mitre.org/tactics/TA0006/)
* **Kỹ thuật (Technique):** [T1003.001 - OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
* **Công cụ / Phương thức sử dụng:** Sysinternals ProcDump / `comsvcs.dll` MiniDump qua Atomic Red Team

---

## 3. TÓM TẮT HÀNH VI TẤN CÔNG (EXECUTIVE SUMMARY)

Vào lúc **22:50 ngày 13/10/2026**, hệ thống Wazuh SIEM ghi nhận cảnh báo mức độ 12 đối với thiết bị `Victim-Pentium-Win10`. Một tiến trình chạy dưới quyền quản trị (High Integrity) đã thực hiện tương tác bất thường vào vùng nhớ của tiến trình hệ thống `lsass.exe` nhằm mục đích trích xuất dữ liệu xác thực (NTLM Hashes / Plaintext Credentials) ra file dump cục bộ trên ổ cứng.

---

## 4. DỮ LIỆU ĐIỀU TRA CHI TIẾT (TECHNICAL TRIAGE & FORENSIC EVIDENCE)

### 4.1. Cây tiến trình (Process Tree Analysis)

```text
powershell.exe (PID: 2140)
└── procdump.exe / rundll32.exe (Target: lsass.exe)
