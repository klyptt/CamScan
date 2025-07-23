
## CAMSCAN

# CamScan is a Python utility for IP camera discovery on networks.

## Capabilities

* **Comprehensive Detection:** Identifies over **60 IP camera manufacturers/types** via signature analysis.
* **Visual Confirmation:** Automatically **captures screenshots** from live camera feeds.
* **Credential Auditing:** Tests over **50 common default username/password combinations**.
* **Multi-Protocol Support:** Integrates with **HTTP, RTSP, and MJPEG**.
* **Adaptive Load Management:** Adjusts scanning speed to **minimize network congestion**.

---

## Getting Started

#### 1. Installation

Install dependencies:

```bash
pip install requests opencv-python pillow urllib3

```

----------

## Usage

Run CamScan from your terminal:

#### Examples:

-   **Single IP:**
```
python camscan.py -t 192.168.1.100
```
- **IP Range (CIDR):**
```
python camscan.py -t 192.168.1.0/24
```
- **Multiple IPs (comma-separated):**
```
python camscan.py -t 192.168.1.10,192.168.1.15
```
## Options

-   `-w` / `--workers`: Set concurrent threads.
    
-   `-T` / `--timeout`: Set request timeout (seconds).
    
-   `-R` / `--retries`: Set request retries.
    
-   `-v` / `--verbose`: Enable detailed logging.

## Important Legal Notice

**Using CamScan to access or scan unauthorized networks or devices is illegal** This includes public networks or those belonging to others without explicit, documented permission. Unauthorized access can lead to severe legal penalties.

This tool is for **legitimate security assessments, personal network management, and educational purposes only, on networks/devices you own or have permission to test.**

### **Example of Illegal Use (DO NOT ATTEMPT):**

Scanning IP ranges like `172.16.0.0/16` or `8.8.8.0/24` (public ranges) without consent is strictly prohibited and illegal. For example, **do not run this command**:
```
python camscan.py -t 8.8.8.0/24
```
