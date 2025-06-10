// WPGuard Frontend JavaScript
class WPGuardApp {
    constructor() {
        this.apiBase = '/api/v1';
        this.currentSection = 'dashboard';
        this.refreshInterval = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupTheme();
        this.loadDashboard();
        this.startAutoRefresh();
    }

    setupEventListeners() {
        // Navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const section = link.dataset.section;
                this.showSection(section);
            });
        });

        // Theme toggle
        document.getElementById('themeToggle').addEventListener('click', () => {
            this.toggleTheme();
        });

        // Refresh button
        document.getElementById('refreshBtn').addEventListener('click', () => {
            this.refreshCurrentSection();
        });

        // Upload form
        this.setupUploadForm();
        
        // FTP form
        this.setupFTPForm();
        
        // Scan management
        this.setupScanManagement();
        
        // Reports
        this.setupReports();
    }

    setupTheme() {
        const savedTheme = localStorage.getItem('wpguard-theme') || 'light';
        document.documentElement.setAttribute('data-theme', savedTheme);
        this.updateThemeIcon(savedTheme);
    }

    toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('wpguard-theme', newTheme);
        this.updateThemeIcon(newTheme);
    }

    updateThemeIcon(theme) {
        const icon = document.querySelector('#themeToggle i');
        icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }

    showSection(section) {
        // Update navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });
        document.querySelector(`[data-section="${section}"]`).classList.add('active');

        // Update sections
        document.querySelectorAll('.section').forEach(sec => {
            sec.classList.remove('active');
        });
        document.getElementById(`${section}-section`).classList.add('active');

        this.currentSection = section;
        this.loadSectionData(section);
    }   

    loadSectionData(section) {
        switch (section) {
            case 'dashboard':
                this.loadDashboard();
                break;
            case 'scans':
                this.loadAllScans();
                break;
            case 'reports':
                this.loadReports();
                break;
            case 'security':
                this.loadAdvancedSecurity();
                break;
            case 'upload':
                // No async data needed
                break;
            case 'ftp':
                // No async data needed
                break;
        }
    }  
    
    async loadDashboard() {
        try {
            const [stats, recentScans] = await Promise.all([
                this.fetchStats(),
                this.fetchRecentScans()
            ]);
            this.updateStats(stats);
            this.updateRecentScansTable(recentScans.scans || []);
        } catch (error) {
            console.error('Failed to load dashboard:', error);
            this.showToast('Failed to load dashboard data', 'error');
        }
    }
    
    async fetchStats() {
        const response = await fetch(`${this.apiBase}/stats`);
        if (!response.ok) throw new Error('Failed to fetch stats');
        return response.json();
    }   

    async fetchRecentScans() {
        const response = await fetch(`${this.apiBase}/scans?limit=10`);
        if (!response.ok) throw new Error('Failed to fetch recent scans');
        return response.json();
    } 

    updateStats(stats) {
        document.getElementById('totalScans').textContent = stats.total_scans || 0;
        document.getElementById('runningScan').textContent = stats.running_scans || 0;
        document.getElementById('cleanSites').textContent = stats.completed_scans || 0;
        // Calculate active threats (scans with suspicious files)
        const activeThreats = (stats.total_scans || 0) - (stats.completed_scans || 0) - (stats.failed_scans || 0);
        document.getElementById('activeThreat').textContent = Math.max(0, activeThreats);
    }  

    updateRecentScansTable(scans) {
        const tbody = document.querySelector('#recentScansTable tbody');
        if (scans.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" style="text-align: center; padding: 2rem; color: var(--text-muted);">
                        No scans found. Upload a WordPress site to get started.
                    </td>
                </tr>
            `;
            return;
        }
        tbody.innerHTML = scans.map(scan => `
            <tr>
                <td>${this.truncateText(scan.scan_id, 20)}</td>
                <td><span class="status-badge">${scan.scan_type}</span></td>
                <td><span class="status-badge status-${scan.status}">${scan.status}</span></td>
                <td>${scan.total_files || 0}</td>
                <td>${scan.suspicious_files || 0}</td>
                <td>${this.formatDate(scan.created_at)}</td>
                <td>
                    <div class="action-buttons">
                        <button class="action-btn" onclick="app.viewScanDetails('${scan.scan_id}')" title="View Details">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="action-btn" onclick="app.viewReport('${scan.scan_id}')" title="View Report">
                            <i class="fas fa-file-alt"></i>
                        </button>
                        <button class="action-btn" onclick="app.deleteScan('${scan.scan_id}')" title="Delete">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
    }
    
    setupUploadForm() {
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const browseBtn = document.getElementById('browseBtn');
        const uploadForm = document.getElementById('uploadForm');
        const clearBtn = document.getElementById('clearUpload');
        // Drag and drop
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            const files = Array.from(e.dataTransfer.files);
            if (files.length > 0) {
                this.handleFileSelection(files[0]);
            }
        });
        // Browse button
        browseBtn.addEventListener('click', () => {
            fileInput.click();
        });
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                this.handleFileSelection(e.target.files[0]);
            }
        });
        // Form submission
        uploadForm.addEventListener('submit', (e) => {
            e.preventDefault();
            this.uploadFile();
        });
        // Clear button
        clearBtn.addEventListener('click', () => {
            this.clearUploadForm();
        });
    }
    handleFileSelection(file) {
        const allowedTypes = ['application/zip', 'application/x-tar', 'application/gzip'];
        const maxSize = 15 * 1024 * 1024 * 1024; // 15GB
        if (!allowedTypes.some(type => file.type === type) && !(file.name.endsWith('.zip') || file.name.endsWith('.tar.gz'))) {
            this.showToast('Please select a ZIP or TAR.GZ file', 'error');
            return;
        }
        if (file.size > maxSize) {
            this.showToast('File size must be less than 15 GB', 'error');
            return;
        }
        document.querySelector('.upload-text h3').textContent = file.name;
        document.querySelector('.upload-text p').textContent = `${this.formatFileSize(file.size)} - Ready to upload`;
        document.getElementById('uploadBtn').disabled = false;
    }

    async uploadFile() {
        const fileInput = document.getElementById('fileInput');
        const scanName = document.getElementById('scanName').value;
        if (!fileInput.files.length) {
            this.showToast('Please select a file to upload', 'error');
            return;
        }
        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        if (scanName) {
            formData.append('scan_name', scanName);
        }
        try {
            this.showUploadProgress(true);
            this.updateUploadProgress(0, 'Uploading file...');
            const response = await this.uploadWithProgress(formData);
            if (response.ok) {
                const result = await response.json();
                this.updateUploadProgress(100, 'Upload complete! Starting scan...');
                // Start scan automatically
                await this.startScan(result.scan_id);
                this.showToast('File uploaded and scan started successfully!', 'success');
                this.clearUploadForm();
                this.showSection('scans');
            } else {
                throw new Error('Upload failed');
            }
        } catch (error) {
            console.error('Upload error:', error);
            this.showToast('Upload failed. Please try again.', 'error');
        } finally {
            this.showUploadProgress(false);
        }
    }

    uploadWithProgress(formData) {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable) {
                    const percentage = Math.round((e.loaded / e.total) * 100);
                    this.updateUploadProgress(percentage, `Uploading... ${percentage}%`);
                }
            });
            xhr.addEventListener('load', () => {
                if (xhr.status >= 200 && xhr.status < 300) {
                    resolve({
                        ok: true,
                        json: () => Promise.resolve(JSON.parse(xhr.responseText))
                    });
                } else {
                    reject(new Error(`HTTP ${xhr.status}`));
                }
            });
            xhr.addEventListener('error', () => {
                reject(new Error('Network error'));
            });
            xhr.open('POST', `${this.apiBase}/upload`);
            xhr.send(formData);
        });
    }
    
    showUploadProgress(show) {
        const progress = document.getElementById('uploadProgress');
        const form = document.getElementById('uploadForm');
        if (show) {
            progress.classList.remove('hidden');
            form.style.opacity = '0.5';
        } else {
            progress.classList.add('hidden');
            form.style.opacity = '1';
        }
    }

    updateUploadProgress(percentage, text) {
        document.getElementById('progressPercent').textContent = `${percentage}%`;
        document.getElementById('progressFill').style.width = `${percentage}%`;
        document.getElementById('progressInfo').textContent = text;
    }

    clearUploadForm() {
        document.getElementById('fileInput').value = '';
        document.getElementById('scanName').value = '';
        document.querySelector('.upload-text h3').textContent = 'Drag & drop your WordPress archive here';
        document.querySelector('.upload-text p').innerHTML = 'or <button type="button" class="link-btn" id="browseBtn">browse files</button>';
        document.getElementById('uploadBtn').disabled = true;
        this.showUploadProgress(false);
        
        // Re-attach browse button event
        document.getElementById('browseBtn').addEventListener('click', () => {
            document.getElementById('fileInput').click();
        });
    }

    setupFTPForm() {
        const ftpForm = document.getElementById('ftpForm');
        const testBtn = document.getElementById('testFtpBtn');
        
        testBtn.addEventListener('click', () => {
            this.testFTPConnection();
        });
        
        ftpForm.addEventListener('submit', (e) => {
            e.preventDefault();
            this.connectFTP();
        });
    }

    async testFTPConnection() {
        const formData = this.getFTPFormData();
        try {
            this.showLoading('Testing FTP connection...');
            const response = await fetch(`${this.apiBase}/ftp/test`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(formData)
            });
            
            if (response.ok) {
                const result = await response.json();
                this.showToast(`Connection successful! Found ${result.remote_files_count} files.`, 'success');
            } else {
                const error = await response.json();
                this.showToast(`Connection failed: ${error.detail || 'Unknown error'}`, 'error');
            }
        } catch (error) {
            console.error('FTP test error:', error);
            this.showToast('Connection test failed. Please check your settings.', 'error');
        } finally {
            this.hideLoading();
        }
    }

    async connectFTP() {
        const formData = this.getFTPFormData();
        try {
            this.showLoading('Connecting to FTP server...');
            const response = await fetch(`${this.apiBase}/ftp`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(formData)
            });
            
            if (response.ok) {
                const result = await response.json();
                this.showToast('Connected successfully! Starting scan...', 'success');
                // Start scan automatically
                await this.startScan(result.scan_id);
                this.showSection('scans');
            } else {
                const error = await response.json();
                this.showToast(`Connection failed: ${error.detail || 'Unknown error'}`, 'error');
            }
        } catch (error) {
            console.error('FTP connect error:', error);
            this.showToast('FTP connection failed. Please try again.', 'error');
        } finally {
            this.hideLoading();
        }
    }

    getFTPFormData() {
        return {
            host: document.getElementById('ftpHost').value,
            port: parseInt(document.getElementById('ftpPort').value) || 21,
            username: document.getElementById('ftpUsername').value,
            password: document.getElementById('ftpPassword').value,
            remote_path: document.getElementById('ftpPath').value || '/public_html',
            scan_name: document.getElementById('ftpScanName').value,
            use_sftp: document.getElementById('useSftp').checked
        };
    }

    async startScan(scanId) {
        try {
            const response = await fetch(`${this.apiBase}/scan/${scanId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    include_malware_scan: true,
                    include_integrity_check: true
                })
            });
            
            if (!response.ok) {
                throw new Error('Failed to start scan');
            }
            
            return await response.json();
        } catch (error) {
            console.error('Start scan error:', error);
            this.showToast('Failed to start scan', 'error');
        }
    }

    setupScanManagement() {
        // Refresh buttons
        document.getElementById('refreshScans').addEventListener('click', () => {
            this.loadDashboard();
        });
        
        document.getElementById('refreshAllScans').addEventListener('click', () => {
            this.loadAllScans();
        });
        
        // Filters
        document.getElementById('applyFilters').addEventListener('click', () => {
            this.loadAllScans();
        });
    }

    async loadAllScans() {
        try {
            const statusFilter = document.getElementById('statusFilter').value;
            const typeFilter = document.getElementById('typeFilter').value;
            
            let url = `${this.apiBase}/scans?limit=50`;
            if (statusFilter) url += `&status=${statusFilter}`;
            if (typeFilter) url += `&scan_type=${typeFilter}`;
            
            const response = await fetch(url);
            if (!response.ok) throw new Error('Failed to fetch scans');
            
            const result = await response.json();
            this.updateAllScansTable(result.scans || []);
        } catch (error) {
            console.error('Failed to load scans:', error);
            this.showToast('Failed to load scans', 'error');
        }
    }

    updateAllScansTable(scans) {
        const tbody = document.querySelector('#allScansTable tbody');
        if (scans.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="9" style="text-align: center; padding: 2rem; color: var(--text-muted);">
                        No scans found matching the current filters.
                    </td>
                </tr>
            `;
            return;
        }
        
        tbody.innerHTML = scans.map(scan => `
            <tr>
                <td>${this.truncateText(scan.scan_id, 20)}</td>
                <td>${scan.scan_name || 'Unnamed'}</td>
                <td><span class="status-badge">${scan.scan_type}</span></td>
                <td><span class="status-badge status-${scan.status}">${scan.status}</span></td>
                <td>${scan.total_files || 0}</td>
                <td>${scan.suspicious_files || 0}</td>
                <td>${this.formatDuration(scan.scan_duration)}</td>
                <td>${this.formatDate(scan.created_at)}</td>
                <td>
                    <div class="action-buttons">
                        <button class="action-btn" onclick="app.viewScanDetails('${scan.scan_id}')" title="View Details">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="action-btn" onclick="app.viewReport('${scan.scan_id}')" title="View Report">
                            <i class="fas fa-file-alt"></i>
                        </button>
                        <button class="action-btn" onclick="app.deleteScan('${scan.scan_id}')" title="Delete">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
    }

    async viewScanDetails(scanId) {
        try {
            this.showLoading('Loading scan details...');
            const response = await fetch(`${this.apiBase}/scan/${scanId}/status`);
            if (!response.ok) throw new Error('Failed to fetch scan details');
            
            const scan = await response.json();
            this.showScanModal(scan);
        } catch (error) {
            console.error('Failed to load scan details:', error);
            this.showToast('Failed to load scan details', 'error');
        } finally {
            this.hideLoading();
        }
    }

    showScanModal(scan) {
        const modal = document.getElementById('scanModal');
        const title = document.getElementById('modalTitle');
        const content = document.getElementById('modalContent');
        
        title.textContent = `Scan Details - ${scan.scan_id}`;
        
        content.innerHTML = `
            <div class="scan-details">
                <div class="details-grid">
                    <div class="detail-item">
                        <label>Scan ID:</label>
                        <span>${scan.scan_id}</span>
                    </div>
                    <div class="detail-item">
                        <label>Type:</label>
                        <span class="status-badge">${scan.scan_type}</span>
                    </div>
                    <div class="detail-item">
                        <label>Status:</label>
                        <span class="status-badge status-${scan.status}">${scan.status}</span>
                    </div>
                    <div class="detail-item">
                        <label>Created:</label>
                        <span>${this.formatDate(scan.created_at)}</span>
                    </div>
                    <div class="detail-item">
                        <label>Started:</label>
                        <span>${scan.started_at ? this.formatDate(scan.started_at) : 'Not started'}</span>
                    </div>
                    <div class="detail-item">
                        <label>Completed:</label>
                        <span>${scan.completed_at ? this.formatDate(scan.completed_at) : 'Not completed'}</span>
                    </div>
                    <div class="detail-item">
                        <label>Total Files:</label>
                        <span>${scan.total_files || 0}</span>
                    </div>
                    <div class="detail-item">
                        <label>Changed Files:</label>
                        <span>${scan.changed_files || 0}</span>
                    </div>
                    <div class="detail-item">
                        <label>New Files:</label>
                        <span>${scan.new_files || 0}</span>
                    </div>
                    <div class="detail-item">
                        <label>Deleted Files:</label>
                        <span>${scan.deleted_files || 0}</span>
                    </div>
                    <div class="detail-item">
                        <label>Suspicious Files:</label>
                        <span class="text-orange">${scan.suspicious_files || 0}</span>
                    </div>
                </div>
            </div>
        `;
        
        modal.classList.remove('hidden');
        
        // Close modal handlers
        document.getElementById('closeScanModal').onclick = () => {
            modal.classList.add('hidden');
        };
        
        modal.onclick = (e) => {
            if (e.target === modal) {
                modal.classList.add('hidden');
            }
        };
    }

    async deleteScan(scanId) {
        if (!confirm('Are you sure you want to delete this scan? This action cannot be undone.')) {
            return;
        }
        
        try {
            this.showLoading('Deleting scan...');
            const response = await fetch(`${this.apiBase}/reports/${scanId}`, {
                method: 'DELETE'
            });
            
            if (response.ok) {
                this.showToast('Scan deleted successfully', 'success');
                this.refreshCurrentSection();
            } else {
                throw new Error('Failed to delete scan');
            }
        } catch (error) {
            console.error('Delete scan error:', error);
            this.showToast('Failed to delete scan', 'error');
        } finally {
            this.hideLoading();
        }
    }

    setupReports() {
        this.loadReports();
    }

    async loadReports() {
        try {
            const response = await fetch(`${this.apiBase}/scans?status=completed&limit=50`);
            if (!response.ok) throw new Error('Failed to fetch reports');
            
            const result = await response.json();
            this.updateReportsGrid(result.scans || []);
        } catch (error) {
            console.error('Failed to load reports:', error);
            this.showToast('Failed to load reports', 'error');
        }
    }

    updateReportsGrid(scans) {
        const grid = document.getElementById('reportsGrid');
        if (scans.length === 0) {
            grid.innerHTML = `
                <div style="text-align: center; padding: 2rem; color: var(--text-muted); grid-column: 1 / -1;">
                    No completed scans found. Complete a scan to view reports.
                </div>
            `;
            return;
        }
        
        grid.innerHTML = scans.map(scan => `
            <div class="report-card" onclick="app.viewReport('${scan.scan_id}')">
                <div class="report-card-header">
                    <div class="report-card-title">${scan.scan_name || scan.scan_id}</div>
                    <div class="report-card-date">${this.formatDate(scan.created_at)}</div>
                </div>
                <div class="report-card-stats">
                    <div class="report-stat">
                        <div class="report-stat-number">${scan.total_files || 0}</div>
                        <div class="report-stat-label">Files</div>
                    </div>
                    <div class="report-stat">
                        <div class="report-stat-number text-orange">${scan.suspicious_files || 0}</div>
                        <div class="report-stat-label">Threats</div>
                    </div>
                    <div class="report-stat">
                        <div class="report-stat-number text-blue">${scan.changed_files || 0}</div>
                        <div class="report-stat-label">Changed</div>
                    </div>
                </div>
                <div class="report-card-footer">
                    <span class="status-badge">${scan.scan_type}</span>
                    <span class="status-badge status-${scan.status}">${scan.status}</span>
                </div>
            </div>
        `).join('');
    }

    async viewReport(scanId) {
        try {
            this.showLoading('Loading report...');
            const response = await fetch(`${this.apiBase}/report/${scanId}`);
            if (!response.ok) throw new Error('Failed to fetch report');
            
            const report = await response.json();
            this.showReportViewer(report);
        } catch (error) {
            console.error('Failed to load report:', error);
            this.showToast('Failed to load report', 'error');
        } finally {
            this.hideLoading();
        }
    }

    showReportViewer(report) {
        const viewer = document.getElementById('reportViewer');
        const listCard = document.getElementById('reportsListCard');
        const title = document.getElementById('reportTitle');
        const content = document.getElementById('reportContent');
        
        title.textContent = `Security Report - ${report.summary.scan_id}`;
        content.innerHTML = this.generateReportHTML(report);
        
        listCard.style.display = 'none';
        viewer.style.display = 'block';
        
        // Close report handler
        document.getElementById('closeReport').onclick = () => {
            viewer.style.display = 'none';
            listCard.style.display = 'block';
        };
        
        // Download report handler
        document.getElementById('downloadReport').onclick = () => {
            this.downloadReport(report);
        };
    }

    generateReportHTML(report) {
        const { summary, findings, recommendations } = report;
        
        return `
            <div class="report-content">
                <!-- Summary Section -->
                <div class="report-section">
                    <h3><i class="fas fa-chart-bar"></i> Scan Summary</h3>
                    <div class="summary-grid">
                        <div class="summary-item">
                            <div class="summary-label">Scan Type</div>
                            <div class="summary-value">${summary.scan_type}</div>
                        </div>
                        <div class="summary-item">
                            <div class="summary-label">Status</div>
                            <div class="summary-value">
                                <span class="status-badge status-${summary.status}">${summary.status}</span>
                            </div>
                        </div>
                        <div class="summary-item">
                            <div class="summary-label">Total Files</div>
                            <div class="summary-value">${summary.total_files_scanned}</div>
                        </div>
                        <div class="summary-item">
                            <div class="summary-label">Suspicious Files</div>
                            <div class="summary-value text-orange">${summary.suspicious_files}</div>
                        </div>
                        <div class="summary-item">
                            <div class="summary-label">Scan Duration</div>
                            <div class="summary-value">${this.formatDuration(summary.scan_duration)}</div>
                        </div>
                        <div class="summary-item">
                            <div class="summary-label">Completed</div>
                            <div class="summary-value">${this.formatDate(summary.completed_at)}</div>
                        </div>
                    </div>
                </div>
                <!-- Risk Assessment -->
                <div class="report-section">
                    <h3><i class="fas fa-exclamation-triangle"></i> Risk Assessment</h3>
                    <div class="risk-grid">
                        <div class="risk-item critical">
                            <div class="risk-number">${summary.critical_findings}</div>
                            <div class="risk-label">Critical</div>
                        </div>
                        <div class="risk-item high">
                            <div class="risk-number">${summary.high_risk_findings}</div>
                            <div class="risk-label">High</div>
                        </div>
                        <div class="risk-item medium">
                            <div class="risk-number">${summary.medium_risk_findings}</div>
                            <div class="risk-label">Medium</div>
                        </div>
                        <div class="risk-item low">
                            <div class="risk-number">${summary.low_risk_findings}</div>
                            <div class="risk-label">Low</div>
                        </div>
                    </div>
                </div>
                <!-- Findings -->
                ${findings && findings.length > 0 ? `
                <div class="report-section">
                    <h3><i class="fas fa-search"></i> Security Findings</h3>
                    <div class="findings-list">
                        ${findings.map(finding => `
                            <div class="finding-item">
                                <div class="finding-header">
                                    <div class="finding-file">${finding.file_path}</div>
                                    <span class="status-badge risk-${finding.risk_level}">${finding.risk_level}</span>
                                </div>
                                <div class="finding-type">${finding.finding_type}</div>
                                <div class="finding-description">${finding.description}</div>
                                ${finding.code_snippet ? `
                                    <div class="finding-code">
                                        <pre><code>${this.escapeHtml(finding.code_snippet)}</code></pre>
                                    </div>
                                ` : ''}
                                ${finding.line_number ? `
                                    <div class="finding-line">Line: ${finding.line_number}</div>
                                ` : ''}
                            </div>
                        `).join('')}
                    </div>
                </div>
                ` : ''}
                <!-- Recommendations -->
                ${recommendations && recommendations.length > 0 ? `
                <div class="report-section">
                    <h3><i class="fas fa-lightbulb"></i> Recommendations</h3>
                    <ul class="recommendations-list">
                        ${recommendations.map(rec => `<li>${rec}</li>`).join('')}
                    </ul>
                </div>
                ` : ''}
                <!-- WordPress Info -->
                ${report.wp_version ? `
                <div class="report-section">
                    <h3><i class="fab fa-wordpress"></i> WordPress Information</h3>
                    <div class="wp-info">
                        <div class="wp-item">
                            <strong>Version:</strong> ${report.wp_version}
                        </div>
                        ${report.wp_plugins ? `
                        <div class="wp-item">
                            <strong>Plugins:</strong> ${report.wp_plugins.join(', ')}
                        </div>
                        ` : ''}
                        ${report.wp_themes ? `
                        <div class="wp-item">
                            <strong>Themes:</strong> ${report.wp_themes.join(', ')}
                        </div>
                        ` : ''}
                    </div>
                </div>
                ` : ''}
            </div>
            <style>
                .report-content { font-size: 0.875rem; }
                .report-section { margin-bottom: 2rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border-color); }
                .report-section:last-child { border-bottom: none; }
                .report-section h3 { margin-bottom: 1rem; color: var(--text-primary); display: flex; align-items: center; gap: 0.5rem; }
                .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }
                .summary-item { text-align: center; }
                .summary-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; }
                .summary-value { font-size: 1.25rem; font-weight: 600; color: var(--text-primary); }
                .risk-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; }
                .risk-item { text-align: center; padding: 1rem; border-radius: var(--radius-md); }
                .risk-item.critical { background-color: rgb(239 68 68 / 0.1); }
                .risk-item.high { background-color: rgb(249 115 22 / 0.1); }
                .risk-item.medium { background-color: rgb(245 158 11 / 0.1); }
                .risk-item.low { background-color: rgb(34 197 94 / 0.1); }
                .risk-number { font-size: 2rem; font-weight: 700; }
                .risk-label { font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); }
                .findings-list { display: flex; flex-direction: column; gap: 1rem; }
                .finding-item { border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 1rem; }
                .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
                .finding-file { font-weight: 600; color: var(--text-primary); }
                .finding-type { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; margin-bottom: 0.5rem; }
                .finding-description { margin-bottom: 0.5rem; }
                .finding-code { background-color: var(--bg-secondary); padding: 0.5rem; border-radius: var(--radius-sm); margin: 0.5rem 0; overflow-x: auto; }
                .finding-code pre { margin: 0; font-size: 0.75rem; }
                .finding-line { font-size: 0.75rem; color: var(--text-muted); }
                .recommendations-list { list-style: none; padding: 0; }
                .recommendations-list li { padding: 0.5rem 0; border-bottom: 1px solid var(--border-color); }
                .recommendations-list li:last-child { border-bottom: none; }
                .wp-info { display: flex; flex-direction: column; gap: 0.5rem; }
                .wp-item { padding: 0.5rem 0; }
            </style>
        `;
    }

    downloadReport(report) {
        const dataStr = JSON.stringify(report, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        
        const link = document.createElement('a');
        link.href = URL.createObjectURL(dataBlob);
        link.download = `wpguard-report-${report.summary.scan_id}.json`;
        link.click();
        
        URL.revokeObjectURL(link.href);
        this.showToast('Report downloaded successfully', 'success');
    }

    startAutoRefresh() {
        this.refreshInterval = setInterval(() => {
            if (this.currentSection === 'dashboard') {
                this.loadDashboard();
            }
        }, 30000); // Refresh every 30 seconds
    }

    refreshCurrentSection() {
        this.loadSectionData(this.currentSection);
    }

    showLoading(text = 'Loading...') {
        const overlay = document.getElementById('loadingOverlay');
        const loadingText = document.getElementById('loadingText');
        loadingText.textContent = text;
        overlay.classList.remove('hidden');
    }

    hideLoading() {
        document.getElementById('loadingOverlay').classList.add('hidden');
    }

    showToast(message, type = 'info', duration = 5000) {
        const container = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;

        const toastId = Date.now();
        toast.innerHTML = `
            <div class="toast-header">
                <div class="toast-title">${this.getToastTitle(type)}</div>
                <button class="toast-close" onclick="app.removeToast(${toastId})">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="toast-message">${message}</div>
        `;

        toast.setAttribute('data-toast-id', toastId);
        container.appendChild(toast);

        // Auto remove after duration
        setTimeout(() => {
            this.removeToast(toastId);
        }, duration);
    }

    getToastTitle(type) {
        const titles = {
            success: 'Success',
            error: 'Error',
            warning: 'Warning',
            info: 'Information'
        };
        return titles[type] || 'Notification';
    }

    removeToast(toastId) {
        const toast = document.querySelector(`[data-toast-id="${toastId}"]`);
        if (toast) {
            toast.remove();
        }
    }

    // Utility functions
    formatDate(dateString) {
        if (!dateString) return 'N/A';
        return new Date(dateString).toLocaleString();
    }

    formatDuration(seconds) {
        if (!seconds) return 'N/A';
        const mins = Math.floor(seconds / 60);
        const secs = Math.floor(seconds % 60);
        return `${mins}m ${secs}s`;
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    truncateText(text, maxLength) {
        if (!text) return '';
        return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
    }

    escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Advanced Security Methods
    async loadAdvancedSecurity() {
        try {
            // Load security metrics
            await this.loadSecurityMetrics();
            
            // Load top threats
            await this.loadTopThreats();
            
            // Load recommendations
            await this.loadSecurityRecommendations();
            
            // Load compliance status
            await this.loadComplianceStatus();
            
            // Setup event listeners
            this.setupAdvancedSecurityEventListeners();
        } catch (error) {
            console.error('Error loading advanced security:', error);
            this.showToast('Failed to load security data', 'error');
        }
    }

    async loadSecurityMetrics() {
        try {
            const response = await fetch('/api/v1/security/metrics');
            const metrics = await response.json();
            
            // Update metric cards
            document.getElementById('mlThreats').textContent = metrics.threat_distribution.critical + metrics.threat_distribution.high;
            document.getElementById('securityScore').textContent = Math.round(100 - metrics.overall_risk_score);
            document.getElementById('complianceScore').textContent = '85'; // From compliance API
            
            const criticalRecommendations = await this.getCriticalRecommendationsCount();
            document.getElementById('criticalRecommendations').textContent = criticalRecommendations;
        } catch (error) {
            console.error('Error loading security metrics:', error);
        }
    }

    async loadTopThreats() {
        try {
            const response = await fetch('/api/v1/security/threats/top');
            const threatData = await response.json();
            
            const container = document.getElementById('threatsContainer');
            if (threatData.top_threats && threatData.top_threats.length > 0) {
                container.innerHTML = threatData.top_threats.map(threat => `
                    <div class="threat-item ${threat.severity}">
                        <div class="threat-header">
                            <div class="threat-type">
                                <i class="fas fa-${this.getThreatIcon(threat.threat_type)}"></i>
                                <span class="threat-name">${this.formatThreatType(threat.threat_type)}</span>
                            </div>
                            <div class="threat-count">
                                <span class="count">${threat.count}</span>
                                <span class="severity-badge ${threat.severity}">${threat.severity.toUpperCase()}</span>
                            </div>
                        </div>
                        <div class="threat-description">${threat.description}</div>
                        <div class="threat-files">
                            <strong>Affected Files:</strong>
                            <ul>
                                ${threat.files.slice(0, 3).map(file => `<li><code>${file}</code></li>`).join('')}
                                ${threat.files.length > 3 ? `<li><em>... and ${threat.files.length - 3} more</em></li>` : ''}
                            </ul>
                        </div>
                    </div>
                `).join('');
            } else {
                container.innerHTML = '<div class="no-data">No threats detected in recent scans</div>';
            }
        } catch (error) {
            console.error('Error loading top threats:', error);
            document.getElementById('threatsContainer').innerHTML = '<div class="error">Failed to load threat data</div>';
        }
    }

    async loadSecurityRecommendations(priority = 'all') {
        try {
            const url = priority === 'all' ? '/api/v1/security/recommendations' : `/api/v1/security/recommendations?priority=${priority}`;
            const response = await fetch(url);
            const recommendations = await response.json();
            
            const container = document.getElementById('recommendationsContainer');
            if (recommendations && recommendations.length > 0) {
                container.innerHTML = recommendations.map(rec => `
                    <div class="recommendation-item ${rec.priority}">
                        <div class="recommendation-header">
                            <div class="rec-priority">
                                <span class="priority-badge ${rec.priority}">${rec.priority.toUpperCase()}</span>
                                <span class="category-badge">${rec.category}</span>
                            </div>
                            <div class="rec-effort">
                                <span class="effort-indicator ${rec.effort}">
                                    <i class="fas fa-${this.getEffortIcon(rec.effort)}"></i>
                                    ${rec.effort} effort
                                </span>
                            </div>
                        </div>
                        <h3 class="rec-title">${rec.title}</h3>
                        <p class="rec-description">${rec.description}</p>
                        <div class="rec-impact">
                            <strong>Impact:</strong> ${rec.impact}
                        </div>
                        <div class="rec-steps">
                            <strong>Steps:</strong>
                            <ol>
                                ${rec.steps.map(step => `<li>${step}</li>`).join('')}
                            </ol>
                        </div>
                    </div>
                `).join('');
            } else {
                container.innerHTML = '<div class="no-data">No recommendations available</div>';
            }
        } catch (error) {
            console.error('Error loading recommendations:', error);
            document.getElementById('recommendationsContainer').innerHTML = '<div class="error">Failed to load recommendations</div>';
        }
    }

    async loadComplianceStatus() {
        try {
            const response = await fetch('/api/v1/security/compliance');
            const compliance = await response.json();
            
            // Update WordPress compliance
            document.getElementById('wpComplianceScore').textContent = compliance.wordpress_compliance.score + '%';
            document.getElementById('wpComplianceScore').className = `compliance-score ${this.getComplianceClass(compliance.wordpress_compliance.score)}`;
            document.getElementById('wpComplianceDetails').innerHTML = this.formatComplianceDetails(compliance.wordpress_compliance);
            
            // Update Web Security compliance
            document.getElementById('webComplianceScore').textContent = compliance.web_security_compliance.score + '%';
            document.getElementById('webComplianceScore').className = `compliance-score ${this.getComplianceClass(compliance.web_security_compliance.score)}`;
            document.getElementById('webComplianceDetails').innerHTML = this.formatComplianceDetails(compliance.web_security_compliance);
            
            // Update File Security compliance
            document.getElementById('fileComplianceScore').textContent = compliance.file_security_compliance.score + '%';
            document.getElementById('fileComplianceScore').className = `compliance-score ${this.getComplianceClass(compliance.file_security_compliance.score)}`;
            document.getElementById('fileComplianceDetails').innerHTML = this.formatComplianceDetails(compliance.file_security_compliance);
        } catch (error) {
            console.error('Error loading compliance status:', error);
        }
    }

    setupAdvancedSecurityEventListeners() {
        // Advanced scan form
        const advancedScanForm = document.getElementById('advancedScanForm');
        if (advancedScanForm) {
            advancedScanForm.addEventListener('submit', (e) => this.handleAdvancedScan(e));
        }

        // Refresh threats button
        const refreshThreatsBtn = document.getElementById('refreshThreats');
        if (refreshThreatsBtn) {
            refreshThreatsBtn.addEventListener('click', () => this.loadTopThreats());
        }

        // View trends button
        const viewTrendsBtn = document.getElementById('viewTrends');
        if (viewTrendsBtn) {
            viewTrendsBtn.addEventListener('click', () => this.showSecurityTrends());
        }

        // Filter tabs for recommendations
        const filterTabs = document.querySelectorAll('.filter-tab');
        filterTabs.forEach(tab => {
            tab.addEventListener('click', (e) => {
                // Update active tab
                filterTabs.forEach(t => t.classList.remove('active'));
                e.target.classList.add('active');
                
                // Load filtered recommendations
                const priority = e.target.dataset.priority;
                this.loadSecurityRecommendations(priority);
            });
        });
    }

    async handleAdvancedScan(event) {
        event.preventDefault();
        const formData = new FormData(event.target);
        
        const scanData = {
            scan_path: document.getElementById('mlScanPath').value,
            scan_name: document.getElementById('mlScanName').value || 'ML Security Scan',
            enable_ml_detection: document.getElementById('enableMlDetection').checked,
            enable_wp_specific: document.getElementById('enableWpSpecific').checked,
            include_compliance: document.getElementById('includeCompliance').checked,
            generate_recommendations: document.getElementById('generateRecommendations').checked,
            max_files: parseInt(document.getElementById('maxFiles').value)
        };

        try {
            this.showLoading('Starting advanced ML scan...');
            
            const response = await fetch('/api/v1/security/scan/advanced', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(scanData)
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            this.hideLoading();
            
            this.showToast(`Advanced scan started! Scan ID: ${result.scan_id}`, 'success');
            
            // Start polling for scan status
            this.pollScanStatus(result.scan_id, 'advanced');
        } catch (error) {
            this.hideLoading();
            console.error('Error starting advanced scan:', error);
            this.showToast('Failed to start advanced scan', 'error');
        }
    }

    async showSecurityTrends() {
        try {
            const response = await fetch('/api/v1/security/trends');
            const trends = await response.json();
            
            // Create modal content for trends
            const modalContent = `
                <div class="trends-dashboard">
                    <h3>Security Trends Analysis</h3>
                    
                    <div class="trend-section">
                        <h4>Threat Trends (Last 30 Days)</h4>
                        <div class="trend-chart">
                            <div class="trend-direction ${trends.threat_trends.trend_direction}">
                                <i class="fas fa-arrow-${trends.threat_trends.trend_direction === 'increasing' ? 'up' : 'down'}"></i>
                                ${trends.threat_trends.trend_direction.toUpperCase()}
                            </div>
                            <div class="trend-velocity">
                                Threat Velocity: ${trends.threat_trends.threat_velocity} threats/day
                            </div>
                        </div>
                    </div>
                    
                    <div class="trend-section">
                        <h4>Security Score History</h4>
                        <div class="score-history">
                            ${trends.security_score_history.map(score => `
                                <div class="score-point">
                                    <span class="date">${new Date(score.date).toLocaleDateString()}</span>
                                    <span class="score">${score.score}</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>
            `;
            
            this.showModal('Security Trends', modalContent);
        } catch (error) {
            console.error('Error loading security trends:', error);
            this.showToast('Failed to load security trends', 'error');
        }
    }

    async getCriticalRecommendationsCount() {
        try {
            const response = await fetch('/api/v1/security/recommendations?priority=critical');
            const recommendations = await response.json();
            return recommendations.length;
        } catch (error) {
            console.error('Error getting critical recommendations count:', error);
            return 0;
        }
    }

    // Helper methods for advanced security
    getThreatIcon(threatType) {
        const icons = {
            'known_malware': 'virus',
            'obfuscated_code': 'eye-slash',
            'suspicious_patterns': 'exclamation-triangle',
            'vulnerability': 'shield-alt',
            'configuration': 'cog'
        };
        return icons[threatType] || 'question-circle';
    }

    formatThreatType(threatType) {
        return threatType.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    getEffortIcon(effort) {
        const icons = {
            'low': 'clock',
            'medium': 'clock',
            'high': 'clock'
        };
        return icons[effort] || 'clock';
    }

    getComplianceClass(score) {
        if (score >= 90) return 'excellent';
        if (score >= 80) return 'good';
        if (score >= 70) return 'fair';
        if (score >= 60) return 'poor';
        return 'critical';
    }

    formatComplianceDetails(compliance) {
        if (compliance.compliant) {
            return '<div class="compliance-status compliant"><i class="fas fa-check-circle"></i> Compliant</div>';
        } else {
            return `
                <div class="compliance-status non-compliant">
                    <i class="fas fa-exclamation-circle"></i> Issues Found
                </div>
                <ul class="compliance-issues">
                    ${compliance.issues.map(issue => `<li>${issue}</li>`).join('')}
                </ul>
            `;
        }
    }
}