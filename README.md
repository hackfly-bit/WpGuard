# WPGuard: WordPress File Integrity Scanner

🛡️ **External Python-based application to scan WordPress files for anomalies, accessible via web, accepting either uploaded site archives or FTP access, and reporting integrity violations or suspicious code.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com/)

## 🚀 Features

- 📁 **Multiple Input Methods**: Upload ZIP/TAR.GZ files or connect via FTP/SFTP
- 🔍 **File Integrity Monitoring**: Generate baseline snapshots and detect changes
- 🦠 **Malware Detection**: Scan for suspicious code patterns and known malware signatures
- 📊 **Comprehensive Reporting**: Detailed findings with risk assessment and recommendations
- 🔄 **Background Processing**: Asynchronous scanning with status tracking
- 🛡️ **Security-First Design**: Pattern matching for WordPress-specific threats
- 📈 **Statistics & Analytics**: Track scan history and security trends

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [API Documentation](#-api-documentation)
- [Usage Examples](#-usage-examples)
- [Scanning Workflow](#-scanning-workflow)
- [Architecture](#-architecture)
- [Development](#-development)
- [Contributing](#-contributing)
- [License](#-license)

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip or Poetry package manager
- 100MB+ available disk space for file processing

### Installation

#### Option 1: Using Poetry (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd wpguard

# Install dependencies
poetry install

# Activate virtual environment
poetry shell

# Run the application
python run.py server
```

#### Option 2: Using pip

```bash
# Clone the repository
git clone <repository-url>
cd wpguard

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python run.py server
```

### 🏃 Running the Application

```bash
# Development server with auto-reload
python run.py server

# Or directly with uvicorn
uvicorn app.main:app --reload --host 0.0.0.0 --port 6000

# Production server
uvicorn app.main:app --host 0.0.0.0 --port 6000 --workers 4
```

The server will start on `http://localhost:6000` with interactive API documentation available at:
- **Swagger UI**: `http://localhost:6000/docs`
- **ReDoc**: `http://localhost:6000/redoc`

## ⚙️ Configuration

Create a `.env` file in the project root (see `.env.example`):

```env
# Server Configuration
HOST=0.0.0.0
PORT=6000
DEBUG=true

# Database
DATABASE_URL=sqlite:///./wpguard.db

# File Upload Settings
UPLOAD_MAX_SIZE=104857600  # 100MB

# FTP Settings
FTP_TIMEOUT=30

# Notifications (Optional)
EMAIL_ENABLED=false
TELEGRAM_ENABLED=false
```

## 📚 API Documentation

### Base URL
All API endpoints are prefixed with `/api/v1`

### 🔐 Authentication
Currently, no authentication is required. For production use, implement authentication middleware.

---

## 📂 Upload Endpoints

### Upload WordPress Archive

**POST** `/api/v1/upload`

Upload a WordPress site archive for scanning.

**Request:**
- **Content-Type**: `multipart/form-data`
- **Body**:
  - `file` (required): ZIP or TAR.GZ file containing WordPress installation
  - `scan_name` (optional): Custom name for the scan

**Response:**
```json
{
  "scan_id": "20231201120000-abc123",
  "status": "uploaded",
  "message": "File uploaded and extracted successfully",
  "wordpress_root": "extracted",
  "total_files": 156,
  "next_steps": "Use POST /api/v1/scan/{scan_id} to start scanning"
}
```

**Example:**
```bash
curl -X POST "http://localhost:6000/api/v1/upload" \
  -F "file=@wordpress-site.zip" \
  -F "scan_name=My WordPress Site"
```

### Upload Status

**GET** `/api/v1/upload/{scan_id}/status`

Get the status of an uploaded scan.

**Response:**
```json
{
  "scan_id": "20231201120000-abc123",
  "scan_type": "upload",
  "status": "pending",
  "created_at": "2023-12-01T12:00:00",
  "metadata": {"scan_name": "My WordPress Site"}
}
```

---

## 🌐 FTP/SFTP Endpoints

### Connect via FTP

**POST** `/api/v1/ftp`

Connect to an FTP/SFTP server and download WordPress files for scanning.

**Request Body:**
```json
{
  "host": "ftp.example.com",
  "port": 21,
  "username": "ftpuser",
  "password": "password",
  "remote_path": "/public_html",
  "scan_name": "Production Site",
  "use_sftp": false
}
```

**Response:**
```json
{
  "scan_id": "20231201120000-def456",
  "status": "connected",
  "message": "FTP connection successful, files downloaded",
  "download_stats": {
    "files_downloaded": 156,
    "total_size": 5242880,
    "errors": []
  },
  "wordpress_root": "downloaded",
  "total_files": 156,
  "next_steps": "Use POST /api/v1/scan/{scan_id} to start scanning"
}
```

### Test FTP Connection

**POST** `/api/v1/ftp/test`

Test FTP connection without downloading files.

**Request Body:** Same as FTP connect
**Response:**
```json
{
  "status": "success",
  "message": "SFTP connection successful",
  "remote_files_count": 156
}
```

---

## 🔍 Scanning Endpoints

### Start Scan

**POST** `/api/v1/scan/{scan_id}`

Start integrity and malware scan for uploaded/FTP files.

**Request Body (Optional):**
```json
{
  "include_malware_scan": true,
  "include_integrity_check": true
}
```

**Response:**
```json
{
  "scan_id": "20231201120000-abc123",
  "status": "started",
  "message": "Scan started in background",
  "check_status": "GET /api/v1/scan/{scan_id}/status"
}
```

### Scan Status

**GET** `/api/v1/scan/{scan_id}/status`

Get current status of a running or completed scan.

**Response:**
```json
{
  "scan_id": "20231201120000-abc123",
  "status": "completed",
  "scan_type": "upload",
  "created_at": "2023-12-01T12:00:00",
  "started_at": "2023-12-01T12:01:00",
  "completed_at": "2023-12-01T12:03:45",
  "total_files": 156,
  "changed_files": 0,
  "new_files": 2,
  "deleted_files": 0,
  "suspicious_files": 1
}
```

**Status Values:**
- `pending` - Scan created but not started
- `running` - Scan in progress
- `completed` - Scan finished successfully
- `failed` - Scan encountered an error

---

## 📊 Reporting Endpoints

### Get Full Report

**GET** `/api/v1/report/{scan_id}`

Get complete scan report with all findings and recommendations.

**Response:**
```json
{
  "summary": {
    "scan_id": "20231201120000-abc123",
    "scan_type": "upload",
    "status": "completed",
    "total_files_scanned": 156,
    "suspicious_files": 1,
    "critical_findings": 0,
    "high_risk_findings": 2,
    "medium_risk_findings": 3,
    "low_risk_findings": 1,
    "scan_duration": 165.5,
    "created_at": "2023-12-01T12:00:00",
    "completed_at": "2023-12-01T12:03:45"
  },
  "findings": [
    {
      "file_path": "wp-content/themes/suspicious/backdoor.php",
      "finding_type": "suspicious_code",
      "risk_level": "high",
      "description": "eval() function call found in backdoor.php",
      "line_number": 15,
      "code_snippet": "eval(base64_decode($_POST['cmd']));",
      "pattern_matched": "eval\\s*\\(",
      "confidence": 0.9
    }
  ],
  "wp_version": "6.3.1",
  "wp_plugins": ["akismet", "woocommerce"],
  "wp_themes": ["twentytwentythree"],
  "recommendations": [
    "🔴 HIGH PRIORITY: Review and address high-risk findings",
    "🔍 Review all suspicious code patterns",
    "🔄 Keep WordPress updated to latest versions"
  ]
}
```

### Get Scan Summary

**GET** `/api/v1/summary/{scan_id}`

Get scan summary with key metrics and risk assessment.

**Response:**
```json
{
  "scan_id": "20231201120000-abc123",
  "scan_type": "upload",
  "status": "completed",
  "created_at": "2023-12-01T12:00:00",
  "completed_at": "2023-12-01T12:03:45",
  "scan_duration": 165.5,
  "total_files": 156,
  "changed_files": 0,
  "new_files": 2,
  "deleted_files": 0,
  "suspicious_files": 1,
  "risk_assessment": {
    "critical_findings": 0,
    "high_risk_findings": 2,
    "medium_risk_findings": 3,
    "low_risk_findings": 1
  },
  "overall_risk": "medium",
  "metadata": {"scan_name": "My WordPress Site"}
}
```

### Get Findings

**GET** `/api/v1/findings/{scan_id}`

Get scan findings with filtering and pagination.

**Query Parameters:**
- `risk_level` (optional): Filter by `critical`, `high`, `medium`, `low`
- `finding_type` (optional): Filter by `suspicious_code`, `new_file`, `changed_file`, `deleted_file`
- `limit` (optional): Number of findings to return (default: 100, max: 1000)
- `offset` (optional): Number of findings to skip (default: 0)

**Response:**
```json
{
  "scan_id": "20231201120000-abc123",
  "total_findings": 6,
  "returned_findings": 3,
  "offset": 0,
  "limit": 3,
  "findings": [...]
}
```

**Example:**
```bash
# Get only high-risk findings
curl "http://localhost:6000/api/v1/findings/20231201120000-abc123?risk_level=high"

# Get suspicious code findings with pagination
curl "http://localhost:6000/api/v1/findings/20231201120000-abc123?finding_type=suspicious_code&limit=10&offset=0"
```

---

## 📋 Management Endpoints

### List All Scans

**GET** `/api/v1/scans`

List all scans with filtering and pagination.

**Query Parameters:**
- `status` (optional): Filter by scan status
- `scan_type` (optional): Filter by `upload` or `ftp`
- `limit` (optional): Number of scans to return (default: 50, max: 500)
- `offset` (optional): Number of scans to skip (default: 0)

**Response:**
```json
{
  "total_scans": 25,
  "returned_scans": 10,
  "offset": 0,
  "limit": 10,
  "scans": [
    {
      "scan_id": "20231201120000-abc123",
      "scan_type": "upload",
      "status": "completed",
      "created_at": "2023-12-01T12:00:00",
      "completed_at": "2023-12-01T12:03:45",
      "total_files": 156,
      "suspicious_files": 1,
      "scan_name": "My WordPress Site"
    }
  ]
}
```

### Get Statistics

**GET** `/api/v1/stats`

Get overall scanning statistics.

**Response:**
```json
{
  "total_scans": 25,
  "completed_scans": 20,
  "running_scans": 1,
  "failed_scans": 2,
  "pending_scans": 2,
  "upload_scans": 15,
  "ftp_scans": 10,
  "recent_scans": 5
}
```

### Delete Scan

**DELETE** `/api/v1/reports/{scan_id}`

Delete scan and all associated files.

**Response:**
```json
{
  "message": "Scan 20231201120000-abc123 and all associated data deleted successfully"
}
```

---

## 🔄 Usage Examples

### Complete Scanning Workflow

#### 1. Upload and Scan WordPress Site

```bash
# 1. Upload WordPress archive
curl -X POST "http://localhost:6000/api/v1/upload" \
  -F "file=@wordpress-site.zip" \
  -F "scan_name=Production Site Scan"

# Response: {"scan_id": "20231201120000-abc123", ...}

# 2. Start scanning
curl -X POST "http://localhost:6000/api/v1/scan/20231201120000-abc123"

# 3. Check scan status
curl "http://localhost:6000/api/v1/scan/20231201120000-abc123/status"

# 4. Get results when completed
curl "http://localhost:6000/api/v1/report/20231201120000-abc123"
```

#### 2. FTP Scanning Workflow

```bash
# 1. Connect and download via FTP
curl -X POST "http://localhost:6000/api/v1/ftp" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "ftp.example.com",
    "username": "ftpuser",
    "password": "password",
    "remote_path": "/public_html",
    "scan_name": "Live Site Scan"
  }'

# 2. Continue with scan steps as above...
```

#### 3. Python Client Example

```python
import requests
import time

# Upload file
with open('wordpress-site.zip', 'rb') as f:
    response = requests.post(
        'http://localhost:6000/api/v1/upload',
        files={'file': f},
        data={'scan_name': 'My Site'}
    )
    scan_id = response.json()['scan_id']

# Start scan
requests.post(f'http://localhost:6000/api/v1/scan/{scan_id}')

# Wait for completion
while True:
    status = requests.get(f'http://localhost:6000/api/v1/scan/{scan_id}/status')
    if status.json()['status'] == 'completed':
        break
    time.sleep(5)

# Get report
report = requests.get(f'http://localhost:6000/api/v1/report/{scan_id}')
print(f"Found {len(report.json()['findings'])} security findings")
```

---

## 🏗️ Scanning Workflow

### 1. File Input Phase
- **Upload**: Extract ZIP/TAR.GZ archives to temporary directory
- **FTP**: Download files from remote server to local directory
- **Validation**: Verify WordPress installation structure

### 2. Baseline Creation
- Generate SHA256 hashes for all files
- Record file metadata (size, permissions, modification time)
- Create baseline snapshot for integrity comparison

### 3. Security Scanning
- **Malware Detection**: Pattern matching against suspicious code signatures
- **Integrity Check**: Compare current state with baseline snapshot
- **WordPress Analysis**: Extract version, plugins, themes information

### 4. Risk Assessment
- Classify findings by risk level (Critical, High, Medium, Low)
- Generate security recommendations
- Calculate overall security score

### 5. Reporting
- Create detailed JSON reports
- Provide API endpoints for accessing results
- Generate actionable recommendations

## ✅ Testing Results

Based on comprehensive testing, WPGuard successfully detected **6 security patterns** in a malicious PHP file:

| Finding Type | Risk Level | Pattern | Description |
|-------------|------------|---------|-------------|
| `eval()` function | **HIGH** | Code execution | Dynamic code evaluation |
| `system()` command | **HIGH** | Command execution | Shell command execution |
| `base64_decode()` | **MEDIUM** | Obfuscation | Base64 decoding for hiding code |
| `str_rot13()` | **MEDIUM** | Obfuscation | ROT13 encoding bypass |
| Unsanitized `$_GET` | **MEDIUM** | Input validation | Direct GET parameter usage |
| Unsanitized `$_POST` | **MEDIUM** | Input validation | Direct POST parameter usage |

All API endpoints tested successfully including file upload, scan execution, status monitoring, and comprehensive reporting.

---

### Project Structure

```
wpguard/
├── app/                          # Main application package
│   ├── api/                      # API endpoint modules
│   │   ├── upload.py            # File upload handling
│   │   ├── ftp.py               # FTP/SFTP connections
│   │   ├── scan.py              # Scan execution
│   │   └── report.py            # Results and reporting
│   ├── scanner/                  # Security scanning modules
│   │   ├── baseline.py          # Baseline snapshot system
│   │   ├── integrity.py         # File integrity checking
│   │   └── malware.py           # Malware pattern detection
│   ├── models/                   # Data models
│   │   ├── scan.py              # Database models
│   │   └── findings.py          # Finding data structures
│   ├── core/                     # Core application modules
│   │   ├── config.py            # Configuration management
│   │   └── database.py          # Database setup
│   └── main.py                   # FastAPI application
├── temp/                         # Temporary file storage
├── snapshots/                    # Baseline snapshots
├── reports/                      # Scan reports
├── tests/                        # Test suite
└── requirements.txt              # Dependencies
```

### Security Patterns Detected

#### PHP Malware Patterns ✅ Verified
- **Code execution**: `eval()`, `system()`, `shell_exec()`, `exec()` (HIGH risk)
- **Obfuscation**: `base64_decode()`, `str_rot13()`, `gzinflate()` (MEDIUM risk)
- **File operations**: `file_get_contents()`, `file_put_contents()` (MEDIUM risk)
- **Input handling**: Unsanitized `$_POST`, `$_GET`, `$_REQUEST` (MEDIUM risk)
- **Dynamic execution**: Variable functions, `call_user_func()` (HIGH risk)
- **Encoding bypass**: Multiple encoding layers, hex encoding (MEDIUM risk)

#### WordPress-Specific Patterns
- Dynamic HTTP requests: `wp_remote_get()`
- Hook manipulation: `add_action()`, `add_filter()` with eval
- Privilege escalation: Admin bypass attempts
- Dynamic script loading: `wp_enqueue_script()`

#### File Integrity Issues
- New files in core directories
- Modified WordPress core files
- Deleted critical files
- Permission changes

---

## 🛠️ Development

### Development Setup

```bash
# Clone repository
git clone <repository-url>
cd wpguard

# Install development dependencies
poetry install --dev

# Run tests
python run.py test
pytest tests/ -v

# Run linting
flake8 app/
black app/

# Start development server
python run.py server
```

### API Testing

Use the interactive documentation:
- **Swagger UI**: `http://localhost:6000/docs`
- **ReDoc**: `http://localhost:6000/redoc`

### Quick API Reference

| Method | Endpoint | Purpose | Status |
|--------|----------|---------|---------|
| `POST` | `/api/v1/upload` | Upload WordPress archive | ✅ Working |
| `GET` | `/api/v1/upload/{id}/status` | Check upload status | ✅ Working |
| `POST` | `/api/v1/ftp` | Connect via FTP/SFTP | ✅ Working |
| `POST` | `/api/v1/ftp/test` | Test FTP connection | ✅ Working |
| `POST` | `/api/v1/scan/{id}` | Start security scan | ✅ Working |
| `GET` | `/api/v1/scan/{id}/status` | Check scan progress | ✅ Working |
| `GET` | `/api/v1/report/{id}` | Get full report | ✅ Working |
| `GET` | `/api/v1/summary/{id}` | Get scan summary | ✅ Fixed |
| `GET` | `/api/v1/findings/{id}` | Get findings with filters | ✅ Working |
| `GET` | `/api/v1/scans` | List all scans | ✅ Working |
| `GET` | `/api/v1/stats` | Get system statistics | ✅ Working |
| `DELETE` | `/api/v1/reports/{id}` | Delete scan data | ✅ Working |

### Adding New Malware Patterns

Edit `app/scanner/malware.py`:

```python
# Add new patterns to _compile_patterns() method
new_patterns = [
    (r"new_suspicious_function\s*\(", "Description", RiskLevel.HIGH),
]
```

### Development Phases

- ✅ **Phase 1**: Project Setup & FastAPI Backend
- ✅ **Phase 2**: File Input Handling (Upload & FTP)  
- ✅ **Phase 3**: Baseline Snapshot System
- ✅ **Phase 4**: File Integrity Checker
- ✅ **Phase 5**: Suspicious Code Detection
- ✅ **Phase 6**: Reporting Backend
- 🔄 **Phase 7**: Frontend Dashboard
- 🔄 **Phase 8**: Scheduler & Notifications
- 🔄 **Phase 9**: Advanced Security Features

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Coding Standards
- Follow PEP 8 style guidelines
- Add type hints to all functions
- Write comprehensive docstrings
- Include unit tests for new features

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🔧 Troubleshooting

### Common Issues & Solutions

#### 1. HTTP 500 Error on `/summary/{scan_id}` Endpoint
**Symptoms**: Internal server error when retrieving scan summary  
**Cause**: Non-serializable None values in database fields  
**Solution**: Updated endpoint with robust null-checking and data type conversion

#### 2. Malware Detection Not Working
**Symptoms**: No malware findings despite suspicious files  
**Solution**: Ensure test files contain proper content:
```php
// Example malicious patterns that trigger detection
eval(base64_decode('malicious_code'));
system($_GET['cmd']);
$malicious = str_rot13('system');
$$malicious($_POST['data']);
```

#### 3. Empty ZIP File Upload Issues
**Symptoms**: Files uploaded but not properly extracted  
**Solution**: Ensure ZIP files are created properly with actual file content

#### 4. Scan Status Stuck in "running"
**Symptoms**: Scan never completes  
**Solution**: Check server logs for background task errors, restart server if needed

#### 5. Database Connection Issues
**Symptoms**: HTTP 500 errors on database operations  
**Solution**: Verify SQLite database file permissions and disk space

---

## 🆘 Support

- **Documentation**: `http://localhost:6000/docs`
- **Issues**: Create an issue on GitHub
- **Discussions**: Use GitHub Discussions for questions

---

## 🔒 Security Notice

WPGuard is designed to detect security issues in WordPress installations. While it identifies many common threats, it should not be considered a complete security solution. Always:

- Keep WordPress and plugins updated
- Use strong authentication
- Implement proper file permissions
- Regular security audits
- Backup your data regularly

**Note**: This tool is for legitimate security testing only. Do not use it on systems you do not own or have permission to test.
