import { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';

export default function ScanExecution() {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('full');
  const [credentialId, setCredentialId] = useState('');
  const [credentialsList, setCredentialsList] = useState<any[]>([]);
  const [status, setStatus] = useState<string | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [jobStatus, setJobStatus] = useState<string | null>(null);
  const [logs, setLogs] = useState<any[]>([]);
  const [history, setHistory] = useState<any[]>([]);
  const [archivedHistory, setArchivedHistory] = useState<any[]>([]);
  const [showArchived, setShowArchived] = useState(false);
  const [filterTarget, setFilterTarget] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [assetResults, setAssetResults] = useState<any[]>([]);
  const [assetJobId, setAssetJobId] = useState<string | null>(null);
  const [assetFilter, setAssetFilter] = useState('');
  const [portScanData, setPortScanData] = useState<any>(null);
  const [portScanJobId, setPortScanJobId] = useState<string | null>(null);
  const [portScanFilter, setPortScanFilter] = useState('');
  const [expandedPortHosts, setExpandedPortHosts] = useState<Record<string, boolean>>({});
  const [serviceData, setServiceData] = useState<any[]>([]);
  const [serviceJobId, setServiceJobId] = useState<string | null>(null);
  const [serviceFilter, setServiceFilter] = useState('');
  const [enumData, setEnumData] = useState<any[]>([]);
  const [enumJobId, setEnumJobId] = useState<string | null>(null);
  const [enumFilter, setEnumFilter] = useState('');
  const [vulnScanData, setVulnScanData] = useState<any[]>([]);
  const [vulnScanJobId, setVulnScanJobId] = useState<string | null>(null);
  const [vulnScanFilter, setVulnScanFilter] = useState('');
  const [authScanData, setAuthScanData] = useState<any[]>([]);
  const [authScanJobId, setAuthScanJobId] = useState<string | null>(null);
  const [authScanFilter, setAuthScanFilter] = useState('');
  const [riskScoringData, setRiskScoringData] = useState<any[]>([]);
  const [riskScoringJobId, setRiskScoringJobId] = useState<string | null>(null);
  const [validationData, setValidationData] = useState<any[]>([]);
  const [validationJobId, setValidationJobId] = useState<string | null>(null);
  const [validationFilter, setValidationFilter] = useState('');
  const logsEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll logs
  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs]);

  const fetchHistory = async () => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch('http://localhost:8000/scan/history', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setHistory(data);
      }
      
      const archRes = await fetch('http://localhost:8000/scan/archived', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (archRes.ok) {
        const archData = await archRes.json();
        setArchivedHistory(archData);
      }
    } catch (err) {
      console.error("Error fetching history", err);
    }
  };

  // Fetch active scan and history on mount
  useEffect(() => {
    const fetchActive = async () => {
      try {
        const token = localStorage.getItem('token');
        const res = await fetch('http://localhost:8000/scan/active', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (res.ok) {
          const data = await res.json();
          if (data && data.scan_job_id) {
            setJobId(data.scan_job_id);
            setJobStatus(data.status);
            setTarget(data.target);
            setScanType(data.scan_type);
            setStatus(`Resumed active scan tracker... Status: ${data.status}`);
          }
        }
      } catch (err) {
        console.error("Error fetching active scan", err);
      }
    };
    
    const fetchCredentials = async () => {
      try {
        const token = localStorage.getItem('token');
        const res = await fetch('http://localhost:8000/credentials/', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (res.ok) {
          setCredentialsList(await res.json());
        }
      } catch (err) {
        console.error("Error fetching credentials", err);
      }
    };

    fetchActive();
    fetchHistory();
    fetchCredentials();
  }, []);

  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (jobId && (jobStatus === 'PENDING' || jobStatus === 'PROCESSING' || jobStatus === 'PAUSED')) {
      interval = setInterval(async () => {
        try {
          const token = localStorage.getItem('token');
          
          // Fetch Status
          const res = await fetch(`http://localhost:8000/scan/${jobId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
          });
          if (res.ok) {
            const data = await res.json();
            // Don't override optimistic updates
            if (jobStatus !== 'STOPPED') {
              setJobStatus(data.status);
              if (data.status === 'COMPLETED') {
                setStatus('Scan completed successfully!');
                fetchHistory(); // refresh history when scan completes
                // Auto-fetch asset discovery results if that profile was used
                if (scanType === 'asset_discovery' && jobId) {
                  fetchAssetResults(jobId);
                }
                if (scanType === 'port_scan' && jobId) {
                  fetchPortScanResults(jobId);
                }
                if (scanType === 'service_fingerprint' && jobId) {
                  fetchServiceResults(jobId);
                }
                if (scanType === 'enumeration' && jobId) {
                  fetchEnumResults(jobId);
                }
                if (scanType === 'vulnerability_scan' && jobId) {
                  fetchVulnScanResults(jobId);
                }
              } else if (data.status === 'STOPPED' || data.status === 'FAILED') {
                setStatus(`Scan ${data.status.toLowerCase()}`);
                fetchHistory(); // refresh history
              } else if (data.status === 'PAUSED') {
                setStatus('Scan paused.');
              } else {
                setStatus(`Scan in progress... Status: ${data.status}`);
              }
            }
          }
          
          // Fetch Logs
          const logRes = await fetch(`http://localhost:8000/scan/${jobId}/logs`, {
            headers: { 'Authorization': `Bearer ${token}` }
          });
          if (logRes.ok) {
            const logData = await logRes.json();
            setLogs(logData);
          }
          
        } catch (err) {
          console.error("Polling error", err);
        }
      }, 2000);
    } else if (jobId && jobStatus === 'COMPLETED') {
      // Fetch final logs once when completed
      const fetchFinalLogs = async () => {
        try {
          const token = localStorage.getItem('token');
          const logRes = await fetch(`http://localhost:8000/scan/${jobId}/logs`, {
            headers: { 'Authorization': `Bearer ${token}` }
          });
          if (logRes.ok) {
            const logData = await logRes.json();
            setLogs(logData);
          }
        } catch (e) {}
      };
      fetchFinalLogs();
    }
    return () => clearInterval(interval);
  }, [jobId, jobStatus]);

  const handleScan = async () => {
    setStatus('Starting scan...');
    setJobId(null);
    setJobStatus(null);
    setLogs([]);
    try {
      const token = localStorage.getItem('token');
      const payload: any = {
        target: target,
        scan_type: scanType
      };
      if ((scanType === 'authenticated' || scanType === 'full_scan') && credentialId) {
        payload.credential_id = parseInt(credentialId);
      }
      
      const response = await fetch('http://localhost:8000/scan/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(payload)
      });

      if (response.ok) {
        const data = await response.json();
        setJobId(data.scan_job_id);
        setJobStatus('PENDING');
        setStatus(`Scan started! Job ID: ${data.scan_job_id}. Waiting for updates...`);
      } else {
        const errData = await response.json().catch(() => null);
        if (response.status === 401 || response.status === 403) {
          setStatus('Error: Unauthorized. Please log in again.');
        } else {
          setStatus(`Error starting scan: ${errData?.detail || response.statusText}`);
        }
      }
    } catch (err) {
      setStatus('Network error. Is the backend running?');
    }
  };

  const handleStopScan = async () => {
    if (!jobId) return;
    
    // Optimistic UI Update for instant feedback
    setJobStatus('STOPPED');
    setStatus('Scan stopped by user.');
    fetchHistory();
    
    try {
      const token = localStorage.getItem('token');
      await fetch(`http://localhost:8000/scan/${jobId}/stop`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
    } catch (err) {
      setStatus('Network error trying to stop scan.');
    }
  };

  const handlePauseScan = async () => {
    if (!jobId) return;
    
    // Optimistic UI Update
    setJobStatus('PAUSED');
    setStatus('Scan paused by user.');
    
    try {
      const token = localStorage.getItem('token');
      await fetch(`http://localhost:8000/scan/${jobId}/pause`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
    } catch (err) {
      setStatus('Network error trying to pause scan.');
    }
  };

  const handleResumeScan = async () => {
    if (!jobId) return;
    
    // Optimistic UI Update
    setJobStatus('PROCESSING');
    setStatus('Resuming scan...');
    
    try {
      const token = localStorage.getItem('token');
      await fetch(`http://localhost:8000/scan/${jobId}/resume`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
    } catch (err) {
      setStatus('Network error trying to resume scan.');
    }
  };
  
  const loadHistoricalLogs = async (oldJobId: string) => {
    try {
      const token = localStorage.getItem('token');
      const logRes = await fetch(`http://localhost:8000/scan/${oldJobId}/logs`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (logRes.ok) {
        const logData = await logRes.json();
        setLogs(logData);
        setJobId(oldJobId);
        setJobStatus('COMPLETED'); // Forces terminal to stay static
        setStatus(`Viewing historical logs for job: ${oldJobId}`);
      }
    } catch (err) {
      console.error("Failed to load historical logs", err);
    }
  };

  const handleDownloadReport = async (downloadJobId: string, format: 'json' | 'csv' = 'json') => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`http://localhost:8000/scan/${downloadJobId}/report?format=${format}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        let blob;
        if (format === 'json') {
            const data = await response.json();
            blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        } else {
            const text = await response.text();
            blob = new Blob([text], { type: 'text/csv' });
        }
        
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scan_report_${downloadJobId.substring(0, 8)}.${format}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      } else {
        alert("Failed to generate report.");
      }
    } catch (err) {
      console.error("Report download error", err);
      alert("Error downloading report.");
    }
  };

  const fetchAssetResults = async (scanJobId: string) => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`http://localhost:8000/scan/${scanJobId}/asset-discovery`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setAssetResults(data);
        setAssetJobId(scanJobId);
        setPortScanData(null); setPortScanJobId(null);
      }
    } catch (err) {
      console.error('Failed to fetch asset discovery results', err);
    }
  };

  const fetchPortScanResults = async (scanJobId: string) => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`http://localhost:8000/scan/${scanJobId}/port-scan`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setPortScanData(data);
        setPortScanJobId(scanJobId);
        setAssetResults([]); setAssetJobId(null);
        setServiceData([]); setServiceJobId(null);
      }
    } catch (err) {
      console.error('Failed to fetch port scan results', err);
    }
  };

  const fetchServiceResults = async (scanJobId: string) => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`http://localhost:8000/scan/${scanJobId}/service-fingerprint`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setServiceData(data);
        setServiceJobId(scanJobId);
        setAssetResults([]); setAssetJobId(null);
        setPortScanData(null); setPortScanJobId(null);
        setEnumData([]); setEnumJobId(null);
      }
    } catch (err) {
      console.error('Failed to fetch service results', err);
    }
  };

  const fetchEnumResults = async (scanJobId: string) => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`http://localhost:8000/scan/${scanJobId}/enumeration`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setEnumData(data);
        setEnumJobId(scanJobId);
        setAssetResults([]); setAssetJobId(null);
        setPortScanData(null); setPortScanJobId(null);
        setServiceData([]); setServiceJobId(null);
        setVulnScanData([]); setVulnScanJobId(null);
      }
    } catch (err) {
      console.error('Failed to fetch enumeration results', err);
    }
  };

  const fetchVulnScanResults = async (scanJobId: string) => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`http://localhost:8000/scan/${scanJobId}/vulnerability-scan`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setVulnScanData(data);
        setVulnScanJobId(scanJobId);
        setAssetResults([]); setAssetJobId(null);
        setPortScanData(null); setPortScanJobId(null);
        setServiceData([]); setServiceJobId(null);
        setEnumData([]); setEnumJobId(null);
      }
    } catch (err) {
      console.error('Failed to fetch vulnerability scan results', err);
    }
  };

  const getTokenRole = () => {
    try {
      const token = localStorage.getItem('token');
      if (!token) return null;
      const payload = JSON.parse(atob(token.split('.')[1]));
      return payload.role;
    } catch (e) {
      return null;
    }
  };
  const userRole = getTokenRole();

  const handleDeleteScan = async (deleteJobId: string) => {
    if (!window.confirm("Are you sure you want to delete this scan? This action cannot be undone.")) return;
    
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`http://localhost:8000/scan/${deleteJobId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (response.ok) {
        setHistory(history.filter(job => job.scan_job_id !== deleteJobId));
        if (jobId === deleteJobId) {
            setJobId(null);
            setJobStatus(null);
            setLogs([]);
            setStatus('Scan deleted.');
        }
      } else {
        const errData = await response.json().catch(() => null);
        alert(`Failed to delete scan: ${errData?.detail || response.statusText}`);
      }
    } catch (err) {
      console.error("Delete scan error", err);
      alert("Network error trying to delete scan.");
    }
  };

  const handleArchiveScan = async (archiveJobId: string) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`http://localhost:8000/scan/${archiveJobId}/archive`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        // Optimistically remove from history and add to archivedHistory, or just refetch
        fetchHistory();
      } else {
        const errData = await response.json().catch(() => null);
        alert(`Failed to archive scan: ${errData?.detail || response.statusText}`);
      }
    } catch (err) {
      console.error("Archive scan error", err);
      alert("Network error trying to archive scan.");
    }
  };

  const handleUnarchiveScan = async (unarchiveJobId: string) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`http://localhost:8000/scan/${unarchiveJobId}/unarchive`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        fetchHistory();
      } else {
        const errData = await response.json().catch(() => null);
        alert(`Failed to unarchive scan: ${errData?.detail || response.statusText}`);
      }
    } catch (err) {
      console.error("Unarchive scan error", err);
      alert("Network error trying to unarchive scan.");
    }
  };

  const isScanning = jobId && (jobStatus === 'PENDING' || jobStatus === 'PROCESSING' || jobStatus === 'PAUSED');
  const loadAuthScanResults = async (oldJobId: string) => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`http://localhost:8000/scan/${oldJobId}/auth-scan`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setAuthScanData(data);
        setAuthScanJobId(oldJobId);
        
        setLogs([]);
        setAssetJobId(null);
        setPortScanJobId(null);
        setServiceJobId(null);
        setEnumJobId(null);
        setVulnScanJobId(null);
        setRiskScoringJobId(null);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const loadRiskScoringResults = async (oldJobId: string) => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`http://localhost:8000/scan/${oldJobId}/risk-scoring`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setRiskScoringData(data);
        setRiskScoringJobId(oldJobId);
        
        setLogs([]);
        setAssetJobId(null);
        setPortScanJobId(null);
        setServiceJobId(null);
        setEnumJobId(null);
        setVulnScanJobId(null);
        setAuthScanJobId(null);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const isActivelyProcessing = (jobStatus === 'PENDING' || jobStatus === 'PROCESSING');

  const sourceHistory = showArchived ? archivedHistory : history;

  const filteredHistory = sourceHistory.filter(job => {
    // Only show completed, failed, or stopped
    if (!['COMPLETED', 'FAILED', 'STOPPED'].includes(job.status)) return false;
    
    // Apply dynamic dropdown filters
    return (
      (filterTarget === '' || job.target === filterTarget) &&
      (filterStatus === '' || job.status === filterStatus)
    );
  });

  return (
    <div className="p-8 flex flex-col gap-8">
      <div className="flex flex-col lg:flex-row gap-8 w-full">
      {/* Input Form & History Section */}
      <div className="flex-1 flex flex-col gap-8 max-w-lg">
        <div>
          <h1 className="text-2xl font-bold mb-6">Execute Scan</h1>
          <div className="bg-white rounded-lg shadow p-6">
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-1">Target (IP, CIDR, Hostname, or Comma-separated list)</label>
              <input 
                type="text" 
                value={target}
                onChange={e => setTarget(e.target.value)}
                disabled={isScanning}
                className="w-full px-3 py-2 border rounded-md disabled:bg-gray-100 disabled:text-gray-500"
                placeholder="e.g. 192.168.1.0/24, 10.0.0.1"
              />
            </div>
            <div className="mb-6">
              <label className="block text-sm font-medium text-gray-700 mb-1">Scan Profile</label>
              <select 
                value={scanType} 
                onChange={e => setScanType(e.target.value)}
                disabled={isScanning} 
                className="w-full px-3 py-2 border rounded-md disabled:bg-gray-100 disabled:text-gray-500"
              >
                <option value="asset_discovery">🔍 Asset Discovery</option>
                <option value="port_scan">🔌 Port Scan</option>
                <option value="service_fingerprint">🛠 Service Detection / Fingerprinting</option>
                <option value="enumeration">📋 System Enumeration</option>
                <option value="vulnerability_scan">🚨 Vulnerability Detection</option>
                <option value="discovery">Discovery Only</option>
                <option value="full_scan">Full Scan (Complete Workflow)</option>
                <option value="authenticated">Authenticated Deep Scan</option>
                <option value="risk_scoring">Risk Scoring / Severity Classification</option>
              </select>
              
              {/* Show credentials dropdown for authenticated scans and full scans */}
              {(scanType === 'authenticated' || scanType === 'full_scan') && (
                <div className="mt-4">
                  <label className="block text-sm font-medium mb-1">Select Credential {scanType === 'full_scan' && <span className="text-gray-400 font-normal">(Optional for full scan)</span>}</label>
                  <select 
                    className="w-full border rounded p-2 focus:ring-2 focus:ring-blue-500 outline-none"
                    value={credentialId}
                    onChange={e => setCredentialId(e.target.value)}
                  >
                    <option value="">-- Select Credential --</option>
                    {credentialsList.map(c => (
                      <option key={c.id} value={c.id}>{c.name} ({c.auth_type})</option>
                    ))}
                  </select>
                </div>
              )}

              {scanType === 'asset_discovery' && (
                <p className="mt-2 text-xs text-indigo-600 bg-indigo-50 px-3 py-2 rounded-md">
                  Discovers live hosts, IPs, hostnames, OS types, routers/firewalls, web apps, containers & cloud instances — without running vulnerability correlation. <br/><br/>
                  <strong>Note:</strong> To discover devices on an entire network, you must enter the target using CIDR notation (e.g., <code>192.168.1.0/24</code>). Entering a single IP address (e.g., <code>192.168.1.1</code>) will only discover that specific device.
                </p>
              )}
              {scanType === 'enumeration' && (
                <p className="mt-2 text-xs text-emerald-700 bg-emerald-50 px-3 py-2 rounded-md">
                  Collects deeper unauthenticated system information to enrich the asset profile. <br/>
                  Extracts: <strong>SMB Shares</strong>, <strong>SNMP System Info</strong>, <strong>DNS Records</strong>, and <strong>SSL Certificates</strong>.
                </p>
              )}
              {scanType === 'vulnerability_scan' && (
                <p className="mt-2 text-xs text-rose-700 bg-rose-50 px-3 py-2 rounded-md">
                  Core vulnerability scanning stage. Matches discovered versions against known weaknesses (CVEs) and runs vulnerability scripts to find misconfigurations like Log4Shell, SMBv1, or default credentials.
                </p>
              )}
              {scanType === 'service_fingerprint' && (
                <p className="mt-2 text-xs text-fuchsia-700 bg-fuchsia-50 px-3 py-2 rounded-md">
                  Figures out exactly what software and versions are running on open ports. <br/>
                  Methods used: Banner grabbing, protocol negotiation, and HTTP response analysis.<br/>
                  Goal: identify software (e.g., Apache 2.4.49, Nginx 1.18, OpenSSH 8.2) for accurate vulnerability matching.
                </p>
              )}
              {scanType === 'port_scan' && (
                <p className="mt-2 text-xs text-purple-700 bg-purple-50 px-3 py-2 rounded-md">
                  Performs comprehensive port enumeration and service detection:
                  <br/>• <strong>TCP SYN Scan</strong> — All 65535 ports (stealth half-open)
                  <br/>• <strong>UDP Scan</strong> — Top service ports (DNS, SNMP, NTP, DHCP, etc.)
                  <br/>• <strong>Service/Version Detection</strong> — Banner grabbing &amp; Nmap probing
                  <br/>• <strong>OS Fingerprinting</strong> — TCP/IP stack analysis
                  <br/>• <strong>NSE Script Scanning</strong> — Default safe enumeration scripts
                  <br/>• <strong>Risk Classification</strong> — Each port rated CRITICAL / HIGH / MEDIUM / LOW
                  <br/><br/>
                  <strong>Tip:</strong> For a single host, enter its IP. For a subnet, use CIDR (e.g., <code>192.168.1.0/24</code>). Port scans on large subnets may take significant time.
                </p>
              )}
            </div>
            
            <div className="flex gap-4">
              <button 
                onClick={handleScan} 
                disabled={isScanning}
                className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50"
              >
                {isActivelyProcessing ? 'Scanning...' : jobStatus === 'PAUSED' ? 'Paused' : 'Start Scan'}
              </button>
              
              {isScanning && (
                <>
                  {jobStatus === 'PAUSED' ? (
                    <button 
                      onClick={handleResumeScan} 
                      className="bg-green-600 text-white px-4 py-2 rounded-md hover:bg-green-700"
                    >
                      Resume
                    </button>
                  ) : (
                    <button 
                      onClick={handlePauseScan} 
                      className="bg-yellow-500 text-white px-4 py-2 rounded-md hover:bg-yellow-600"
                    >
                      Pause
                    </button>
                  )}
                  
                  <button 
                    onClick={handleStopScan} 
                    className="bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700"
                  >
                    Stop Scan
                  </button>
                </>
              )}
            </div>
            
            {status && (
              <div className={`mt-4 p-4 rounded-md border ${status.includes('Error') ? 'bg-red-50 border-red-200 text-red-800' : 'bg-blue-50 border-blue-200 text-blue-800'}`}>
                <p className="font-medium">{status}</p>
                {jobStatus === 'COMPLETED' && jobId && (
                  <div className="mt-3 flex space-x-4">
                    <button 
                      onClick={() => handleDownloadReport(jobId, 'json')} 
                      className="text-sm font-medium text-blue-600 hover:underline flex items-center"
                    >
                      <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                      Report (JSON)
                    </button>
                    <button 
                      onClick={() => handleDownloadReport(jobId, 'csv')} 
                      className="text-sm font-medium text-green-600 hover:underline flex items-center"
                    >
                      <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                      Report (CSV)
                    </button>
                    <Link to="/devices" className="text-sm text-blue-600 hover:underline">Global Devices</Link>
                    <Link to="/findings" className="text-sm text-blue-600 hover:underline">Global Findings</Link>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

      </div>

      {/* Right Panel: Asset Discovery Results OR Terminal Console */}
      <div className="flex-1 flex flex-col max-h-[900px]">
        {riskScoringData && riskScoringJobId ? (
          /* ── Risk Scoring Results Panel ── */
          <>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold">🎯 Contextual Risk Scoring Results
                <span className="ml-2 text-sm font-normal text-gray-500">({riskScoringData.length} vulnerabilities processed)</span>
              </h2>
              <button
                onClick={() => { setRiskScoringData([]); setRiskScoringJobId(null); }}
                className="text-sm text-gray-400 hover:text-gray-600"
              >✕ Close</button>
            </div>
            <div className="overflow-y-auto flex-1 bg-white rounded shadow border">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Target IP</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Vulnerability</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Base Score</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Adjusted Score</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Final Severity</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200 text-sm">
                  {riskScoringData.map(r => (
                    <tr key={r.id}>
                      <td className="px-4 py-4 whitespace-nowrap">{r.ip_address}</td>
                      <td className="px-4 py-4">
                        <div className="font-medium text-gray-900">{r.vulnerability_id}</div>
                        <div className="text-xs text-gray-500 mt-1 flex gap-2">
                          {r.environmental_factors.is_publicly_exposed && <span className="bg-red-100 text-red-800 px-1.5 py-0.5 rounded">Public IP</span>}
                          {r.environmental_factors.is_kev && <span className="bg-orange-100 text-orange-800 px-1.5 py-0.5 rounded">KEV</span>}
                        </div>
                      </td>
                      <td className="px-4 py-4">
                        <div className="flex items-center">
                          <span className="text-gray-600 w-8">{r.base_score.toFixed(1)}</span>
                          <span className="text-xs text-gray-400 ml-2">({r.base_severity})</span>
                        </div>
                      </td>
                      <td className="px-4 py-4">
                        <span className="font-medium">{r.adjusted_score.toFixed(1)}</span>
                        {r.adjusted_score > r.base_score && (
                          <span className="ml-2 text-xs text-red-500">↑ {((r.adjusted_score - r.base_score)).toFixed(1)}</span>
                        )}
                      </td>
                      <td className="px-4 py-4">
                        <span className={`px-2 py-1 text-xs font-semibold rounded-full ${
                          r.final_severity === 'Critical' ? 'bg-red-100 text-red-800' :
                          r.final_severity === 'High' ? 'bg-orange-100 text-orange-800' :
                          r.final_severity === 'Medium' ? 'bg-yellow-100 text-yellow-800' :
                          'bg-green-100 text-green-800'
                        }`}>
                          {r.final_severity}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        ) : authScanData && authScanJobId ? (
          /* ── Authenticated Scan Results Panel ── */
          <>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold">🔑 Authenticated Scan Results
                <span className="ml-2 text-sm font-normal text-gray-500">({authScanData.length} items found)</span>
              </h2>
              <button
                onClick={() => { setAuthScanData(null); setAuthScanJobId(null); }}
                className="text-sm text-gray-400 hover:text-gray-600"
              >✕ Close</button>
            </div>
            <div className="overflow-y-auto flex-1 bg-white p-4 rounded shadow border">
              <pre className="text-xs font-mono">{JSON.stringify(authScanData, null, 2)}</pre>
            </div>
          </>
        ) : portScanData && portScanJobId ? (
          /* ── Port Scan Results Panel ── */
          <>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold">🔌 Port Scan Results
                <span className="ml-2 text-sm font-normal text-gray-500">({portScanData.ports?.length || 0} ports across {portScanData.summaries?.length || 0} host(s))</span>
              </h2>
              <button
                onClick={() => { setPortScanData(null); setPortScanJobId(null); }}
                className="text-sm text-gray-400 hover:text-gray-600"
              >✕ Close</button>
            </div>

            {/* Risk summary badges */}
            <div className="flex flex-wrap gap-2 mb-4">
              {(['CRITICAL','HIGH','MEDIUM','LOW'] as const).map(risk => {
                const count = portScanData.ports?.filter((p: any) => p.risk === risk).length || 0;
                if (!count) return null;
                const colorMap: Record<string,string> = {
                  CRITICAL:'bg-red-100 text-red-800',
                  HIGH:'bg-orange-100 text-orange-800',
                  MEDIUM:'bg-yellow-100 text-yellow-800',
                  LOW:'bg-green-100 text-green-800',
                };
                return (
                  <span key={risk} className={`px-2 py-1 rounded-full text-xs font-semibold ${colorMap[risk]}`}>
                    {risk} ({count})
                  </span>
                );
              })}
              <span className="px-2 py-1 rounded-full text-xs font-semibold bg-blue-100 text-blue-800">
                TCP: {portScanData.ports?.filter((p: any) => p.protocol === 'tcp').length || 0}
              </span>
              <span className="px-2 py-1 rounded-full text-xs font-semibold bg-indigo-100 text-indigo-800">
                UDP: {portScanData.ports?.filter((p: any) => p.protocol === 'udp').length || 0}
              </span>
            </div>

            {/* Filter */}
            <input
              type="text"
              placeholder="Filter by IP, port, service, product…"
              value={portScanFilter}
              onChange={e => setPortScanFilter(e.target.value)}
              className="mb-3 w-full px-3 py-2 border rounded-md text-sm"
            />

            {/* Per-host expandable sections */}
            <div className="overflow-y-auto flex-1 space-y-3 pr-1">
              {(portScanData.summaries || []).map((summary: any) => {
                const isExpanded = !!expandedPortHosts[summary.ip_address];
                const hostPorts = (portScanData.ports || []).filter((p: any) => {
                  if (p.ip_address !== summary.ip_address) return false;
                  if (!portScanFilter) return true;
                  const q = portScanFilter.toLowerCase();
                  return (
                    p.ip_address.toLowerCase().includes(q) ||
                    String(p.port).includes(q) ||
                    (p.service||'').toLowerCase().includes(q) ||
                    (p.product||'').toLowerCase().includes(q) ||
                    (p.risk||'').toLowerCase().includes(q)
                  );
                });

                const riskColor: Record<string,string> = {
                  CRITICAL:'border-red-500 bg-red-50',
                  HIGH:'border-orange-400 bg-orange-50',
                  MEDIUM:'border-yellow-400 bg-yellow-50',
                  LOW:'border-green-400 bg-green-50',
                };
                const riskBadge: Record<string,string> = {
                  CRITICAL:'bg-red-600 text-white',
                  HIGH:'bg-orange-500 text-white',
                  MEDIUM:'bg-yellow-500 text-white',
                  LOW:'bg-green-600 text-white',
                };

                return (
                  <div key={summary.ip_address} className={`rounded-lg shadow-sm border-l-4 ${riskColor[summary.overall_risk] || 'border-gray-300 bg-white'}`}>
                    {/* Host header */}
                    <div
                      className="p-4 cursor-pointer hover:bg-white/50 transition-colors"
                      onClick={() => setExpandedPortHosts(prev => ({ ...prev, [summary.ip_address]: !prev[summary.ip_address] }))}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <svg className={`w-4 h-4 transform transition-transform ${isExpanded ? 'rotate-90' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                          </svg>
                          <span className="font-bold text-gray-900">{summary.ip_address}</span>
                          {summary.hostname && <span className="text-xs text-gray-500">({summary.hostname})</span>}
                          <span className={`text-xs font-bold px-2 py-0.5 rounded ${riskBadge[summary.overall_risk] || 'bg-gray-400 text-white'}`}>
                            {summary.overall_risk}
                          </span>
                        </div>
                        <div className="flex items-center gap-4 text-xs text-gray-600">
                          <span>TCP: <strong>{summary.tcp_open}</strong></span>
                          <span>UDP: <strong>{summary.udp_open}</strong></span>
                          <span>Total: <strong>{summary.total_open_ports}</strong></span>
                        </div>
                      </div>
                      {summary.os_name && (
                        <p className="text-xs text-gray-500 mt-1 ml-7">🖥 {summary.os_name}{summary.os_accuracy ? ` (${summary.os_accuracy}%)` : ''}</p>
                      )}
                    </div>

                    {/* Expanded port table */}
                    {isExpanded && (
                      <div className="px-4 pb-4">
                        <table className="w-full text-xs border-collapse">
                          <thead>
                            <tr className="bg-gray-100 text-gray-600">
                              <th className="px-2 py-1.5 text-left font-semibold">Port</th>
                              <th className="px-2 py-1.5 text-left font-semibold">Proto</th>
                              <th className="px-2 py-1.5 text-left font-semibold">State</th>
                              <th className="px-2 py-1.5 text-left font-semibold">Service</th>
                              <th className="px-2 py-1.5 text-left font-semibold">Product / Version</th>
                              <th className="px-2 py-1.5 text-left font-semibold">Risk</th>
                              <th className="px-2 py-1.5 text-left font-semibold">Method</th>
                            </tr>
                          </thead>
                          <tbody>
                            {hostPorts.length === 0 ? (
                              <tr><td colSpan={7} className="px-2 py-3 text-center text-gray-400 italic">No ports match filter</td></tr>
                            ) : (
                              hostPorts.map((p: any) => {
                                const portRiskColor: Record<string,string> = {
                                  CRITICAL:'text-red-700 font-bold',
                                  HIGH:'text-orange-600 font-semibold',
                                  MEDIUM:'text-yellow-700',
                                  LOW:'text-green-700',
                                };
                                return (
                                  <tr key={`${p.port}-${p.protocol}`} className="border-b border-gray-100 hover:bg-gray-50">
                                    <td className="px-2 py-1.5 font-mono font-bold">{p.port}</td>
                                    <td className="px-2 py-1.5 uppercase">{p.protocol}</td>
                                    <td className="px-2 py-1.5">
                                      <span className="bg-green-100 text-green-800 px-1.5 py-0.5 rounded text-[10px] font-semibold">{p.state}</span>
                                    </td>
                                    <td className="px-2 py-1.5 font-medium">{p.service || '—'}</td>
                                    <td className="px-2 py-1.5">
                                      {p.product ? `${p.product} ${p.version || ''}`.trim() : (p.banner ? <span className="italic text-gray-400">{p.banner.substring(0,40)}…</span> : '—')}
                                      {p.cpe && <span className="block text-[10px] text-gray-400 font-mono">{p.cpe}</span>}
                                    </td>
                                    <td className={`px-2 py-1.5 ${portRiskColor[p.risk] || ''}`}>{p.risk}</td>
                                    <td className="px-2 py-1.5 text-gray-400">{p.scan_method || '—'}</td>
                                  </tr>
                                );
                              })
                            )}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </>
        ) : serviceData.length > 0 && serviceJobId ? (
          /* ── Service Fingerprint Results Panel ── */
          <>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold">🛠 Service Fingerprint Results
                <span className="ml-2 text-sm font-normal text-gray-500">({serviceData.length} services identified)</span>
              </h2>
              <button
                onClick={() => { setServiceData([]); setServiceJobId(null); }}
                className="text-sm text-gray-400 hover:text-gray-600"
              >✕ Close</button>
            </div>

            <input
              type="text"
              placeholder="Filter by IP, port, product, banner…"
              value={serviceFilter}
              onChange={e => setServiceFilter(e.target.value)}
              className="mb-3 w-full px-3 py-2 border rounded-md text-sm"
            />

            <div className="overflow-y-auto flex-1 space-y-3 pr-1">
              <table className="min-w-full text-sm border-collapse bg-white rounded-lg shadow-sm overflow-hidden">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    <th className="px-4 py-3 text-left font-semibold text-gray-600">Target</th>
                    <th className="px-4 py-3 text-left font-semibold text-gray-600">Port</th>
                    <th className="px-4 py-3 text-left font-semibold text-gray-600">Service</th>
                    <th className="px-4 py-3 text-left font-semibold text-gray-600">Product / Version</th>
                    <th className="px-4 py-3 text-left font-semibold text-gray-600">Banner / Extrainfo</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {serviceData
                    .filter(s => {
                      if (!serviceFilter) return true;
                      const q = serviceFilter.toLowerCase();
                      return (
                        s.ip_address.toLowerCase().includes(q) ||
                        String(s.port).includes(q) ||
                        (s.product||'').toLowerCase().includes(q) ||
                        (s.banner||'').toLowerCase().includes(q) ||
                        (s.service||'').toLowerCase().includes(q)
                      );
                    })
                    .map((s: any) => (
                      <tr key={s.id} className="hover:bg-gray-50">
                        <td className="px-4 py-3 font-medium text-gray-900">{s.ip_address}</td>
                        <td className="px-4 py-3 font-mono">
                          <span className="bg-gray-100 px-2 py-0.5 rounded text-gray-700">{s.port}/{s.protocol}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="font-semibold text-gray-700">{s.service || 'unknown'}</span>
                        </td>
                        <td className="px-4 py-3">
                          {s.product ? (
                            <div>
                              <span className="font-bold text-blue-700">{s.product}</span>
                              {s.version && <span className="ml-1 text-blue-600">{s.version}</span>}
                            </div>
                          ) : s.http_server ? (
                            <span className="text-teal-700 font-medium">{s.http_server}</span>
                          ) : (
                            <span className="text-gray-400 italic">Not identified</span>
                          )}
                          {s.cpe && <div className="text-[10px] text-gray-500 font-mono mt-1">{s.cpe}</div>}
                        </td>
                        <td className="px-4 py-3 text-xs text-gray-600">
                          {s.extrainfo && <div className="font-medium text-gray-800 mb-1">{s.extrainfo}</div>}
                          {s.banner && (
                            <div className="bg-gray-50 p-1.5 rounded border border-gray-200 font-mono text-[10px] max-h-24 overflow-y-auto whitespace-pre-wrap">
                              {s.banner}
                            </div>
                          )}
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </>
        ) : enumData.length > 0 && enumJobId ? (
          /* ── Enumeration Results Panel ── */
          <>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold">📋 System Enumeration Results
                <span className="ml-2 text-sm font-normal text-gray-500">({enumData.length} hosts scanned)</span>
              </h2>
              <button
                onClick={() => { setEnumData([]); setEnumJobId(null); }}
                className="text-sm text-gray-400 hover:text-gray-600"
              >✕ Close</button>
            </div>

            <input
              type="text"
              placeholder="Filter by IP…"
              value={enumFilter}
              onChange={e => setEnumFilter(e.target.value)}
              className="mb-3 w-full px-3 py-2 border rounded-md text-sm"
            />

            <div className="overflow-y-auto flex-1 space-y-4 pr-1">
              {enumData
                .filter(e => !enumFilter || e.ip_address.toLowerCase().includes(enumFilter.toLowerCase()))
                .map((item: any) => (
                  <div key={item.id} className="bg-white rounded-lg shadow-sm border border-emerald-100 overflow-hidden">
                    <div className="bg-emerald-50 px-4 py-3 border-b border-emerald-100 flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-gray-900 text-lg">{item.ip_address}</span>
                        {item.os_info && <span className="text-xs bg-emerald-100 text-emerald-800 px-2 py-0.5 rounded-full">{item.os_info}</span>}
                      </div>
                    </div>
                    
                    <div className="p-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
                      {/* SMB Shares */}
                      {item.smb_shares && item.smb_shares.length > 0 && (
                        <div className="bg-gray-50 rounded p-3 border border-gray-100">
                          <h4 className="font-semibold text-gray-700 mb-2 text-sm flex items-center">📁 SMB Shares</h4>
                          <div className="space-y-2">
                            {item.smb_shares.map((share: any, idx: number) => (
                              <pre key={idx} className="text-[10px] bg-white p-2 rounded border border-gray-200 overflow-x-auto text-gray-600">
                                {share.raw_output}
                              </pre>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* SNMP */}
                      {(item.snmp_sysdescr || (item.snmp_interfaces && item.snmp_interfaces.length > 0)) && (
                        <div className="bg-gray-50 rounded p-3 border border-gray-100">
                          <h4 className="font-semibold text-gray-700 mb-2 text-sm flex items-center">📡 SNMP Information</h4>
                          {item.snmp_sysdescr && (
                            <div className="mb-2">
                              <span className="text-xs font-semibold text-gray-500">System Description:</span>
                              <p className="text-xs text-gray-700">{item.snmp_sysdescr}</p>
                            </div>
                          )}
                          {item.snmp_interfaces && item.snmp_interfaces.length > 0 && (
                            <div>
                              <span className="text-xs font-semibold text-gray-500">Interfaces:</span>
                              {item.snmp_interfaces.map((intf: string, idx: number) => (
                                <pre key={idx} className="text-[10px] bg-white p-2 rounded border border-gray-200 mt-1 overflow-x-auto text-gray-600">
                                  {intf}
                                </pre>
                              ))}
                            </div>
                          )}
                        </div>
                      )}

                      {/* SSL Certs */}
                      {item.ssl_certs && item.ssl_certs.length > 0 && (
                        <div className="bg-gray-50 rounded p-3 border border-gray-100 lg:col-span-2">
                          <h4 className="font-semibold text-gray-700 mb-2 text-sm flex items-center">🔐 SSL Certificates</h4>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {item.ssl_certs.map((cert: any, idx: number) => (
                              <div key={idx} className="bg-white p-2 rounded border border-gray-200">
                                <span className="text-xs font-bold text-gray-700 block mb-1">Port {cert.port}</span>
                                <pre className="text-[10px] text-gray-600 overflow-x-auto">{cert.details}</pre>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* DNS */}
                      {item.dns_records && item.dns_records.length > 0 && (
                        <div className="bg-gray-50 rounded p-3 border border-gray-100 lg:col-span-2">
                          <h4 className="font-semibold text-gray-700 mb-2 text-sm flex items-center">🌍 DNS Records</h4>
                          <div className="space-y-2">
                            {item.dns_records.map((rec: string, idx: number) => (
                              <pre key={idx} className="text-[10px] bg-white p-2 rounded border border-gray-200 overflow-x-auto text-gray-600">
                                {rec}
                              </pre>
                            ))}
                          </div>
                        </div>
                      )}
                      
                      {!item.smb_shares?.length && !item.snmp_sysdescr && !item.ssl_certs?.length && !item.dns_records?.length && (
                        <div className="col-span-full p-4 text-center text-gray-400 italic">
                          No enumeration data was successfully extracted from this host.
                        </div>
                      )}
                    </div>
                  </div>
                ))}
            </div>
          </>
        ) : vulnScanData.length > 0 && vulnScanJobId ? (
          /* ── Vulnerability Scan Results Panel ── */
          <>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold">🚨 Vulnerability Scan Results
                <span className="ml-2 text-sm font-normal text-gray-500">({vulnScanData.length} services affected)</span>
              </h2>
              <button
                onClick={() => { setVulnScanData([]); setVulnScanJobId(null); }}
                className="text-sm text-gray-400 hover:text-gray-600"
              >✕ Close</button>
            </div>

            <input
              type="text"
              placeholder="Filter by IP, Product, or CVE…"
              value={vulnScanFilter}
              onChange={e => setVulnScanFilter(e.target.value)}
              className="mb-3 w-full px-3 py-2 border rounded-md text-sm"
            />

            <div className="overflow-y-auto flex-1 space-y-4 pr-1">
              {vulnScanData
                .filter(e => !vulnScanFilter || 
                  e.ip_address.toLowerCase().includes(vulnScanFilter.toLowerCase()) || 
                  e.product?.toLowerCase().includes(vulnScanFilter.toLowerCase()) ||
                  e.cves?.some((c:any) => c.id.toLowerCase().includes(vulnScanFilter.toLowerCase()))
                )
                .map((item: any) => (
                  <div key={item.id} className="bg-white rounded-lg shadow-sm border border-rose-100 overflow-hidden">
                    <div className="bg-rose-50 px-4 py-3 border-b border-rose-100 flex flex-col md:flex-row md:items-center justify-between gap-2">
                      <div className="flex items-center gap-3">
                        <span className="font-bold text-gray-900 text-lg">{item.ip_address}</span>
                        <span className="text-xs bg-gray-200 text-gray-800 px-2 py-0.5 rounded-full font-mono">{item.port}/{item.protocol}</span>
                        <span className="text-sm text-gray-600 font-medium">{item.service.toUpperCase()}</span>
                      </div>
                      {item.product && (
                        <span className="text-sm font-mono bg-white px-2 py-1 rounded text-rose-800 border border-rose-200">
                          {item.product}
                        </span>
                      )}
                    </div>
                    
                    <div className="p-4 space-y-4">
                      {/* CVEs */}
                      {item.cves && item.cves.length > 0 && (
                        <div>
                          <h4 className="font-semibold text-gray-700 mb-2 text-sm flex items-center border-b pb-1">
                            🐞 Known Vulnerabilities (CVEs)
                          </h4>
                          <div className="grid grid-cols-1 xl:grid-cols-2 gap-3 mt-2">
                            {item.cves.map((cve: any, idx: number) => (
                              <div key={idx} className="bg-white p-3 rounded border border-gray-200 shadow-sm flex flex-col gap-2 relative overflow-hidden">
                                <div className={`absolute top-0 left-0 w-1 h-full ${cve.severity === 'Critical' ? 'bg-purple-600' : cve.severity === 'High' ? 'bg-red-500' : 'bg-orange-400'}`}></div>
                                <div className="flex justify-between items-start pl-2">
                                  <span className="font-bold text-rose-700">{cve.id}</span>
                                  <span className={`text-xs px-2 py-1 rounded-full font-bold ${cve.severity === 'Critical' ? 'bg-purple-100 text-purple-800' : cve.severity === 'High' ? 'bg-red-100 text-red-800' : 'bg-orange-100 text-orange-800'}`}>
                                    {cve.severity} (CVSS: {cve.cvss})
                                  </span>
                                </div>
                                <p className="text-xs text-gray-600 pl-2">{cve.description}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Misconfigurations */}
                      {item.misconfigurations && item.misconfigurations.length > 0 && (
                        <div>
                          <h4 className="font-semibold text-gray-700 mb-2 text-sm flex items-center border-b pb-1">
                            ⚙️ Misconfigurations & Script Findings
                          </h4>
                          <div className="space-y-2 mt-2">
                            {item.misconfigurations.map((misc: any, idx: number) => (
                              <div key={idx} className="bg-gray-50 rounded p-3 border border-gray-200">
                                <div className="flex justify-between items-start mb-2">
                                  <span className="font-bold text-amber-700 font-mono text-sm">{misc.id}</span>
                                  <span className={`text-xs px-2 py-0.5 rounded-full font-bold ${misc.severity === 'Critical' ? 'bg-purple-100 text-purple-800' : misc.severity === 'High' ? 'bg-red-100 text-red-800' : 'bg-orange-100 text-orange-800'}`}>
                                    {misc.severity}
                                  </span>
                                </div>
                                <p className="text-xs text-gray-700 mb-2">{misc.description}</p>
                                <details className="text-xs">
                                  <summary className="cursor-pointer text-indigo-600 font-medium">Show raw output</summary>
                                  <pre className="mt-2 p-2 bg-gray-800 text-gray-100 rounded overflow-x-auto">
                                    {misc.raw_output}
                                  </pre>
                                </details>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {!item.cves?.length && !item.misconfigurations?.length && (
                        <div className="p-4 text-center text-gray-400 italic">
                          No vulnerabilities were detected for this service.
                        </div>
                      )}
                    </div>
                  </div>
                ))}
            </div>
          </>
        ) : assetResults.length > 0 && assetJobId ? (
          /* ── Asset Discovery Results Panel ── */
          <>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold">🔍 Asset Discovery Results
                <span className="ml-2 text-sm font-normal text-gray-500">({assetResults.length} assets)</span>
              </h2>
              <button
                onClick={() => { setAssetResults([]); setAssetJobId(null); }}
                className="text-sm text-gray-400 hover:text-gray-600"
              >✕ Close</button>
            </div>

            {/* Summary badges */}
            <div className="flex flex-wrap gap-2 mb-4">
              {(['network_device','web_server','container_host','cloud_instance','server','windows_host','linux_host','host'] as const).map(role => {
                const count = assetResults.filter(a => a.role === role).length;
                if (!count) return null;
                const colorMap: Record<string,string> = {
                  network_device:'bg-orange-100 text-orange-800',
                  web_server:'bg-blue-100 text-blue-800',
                  container_host:'bg-purple-100 text-purple-800',
                  cloud_instance:'bg-sky-100 text-sky-800',
                  server:'bg-green-100 text-green-800',
                  windows_host:'bg-indigo-100 text-indigo-800',
                  linux_host:'bg-teal-100 text-teal-800',
                  host:'bg-gray-100 text-gray-700',
                };
                const labelMap: Record<string,string> = {
                  network_device:'🌐 Network Device',web_server:'🌍 Web Server',
                  container_host:'🐳 Container Host',cloud_instance:'☁ Cloud Instance',
                  server:'🖥 Server',windows_host:'🪟 Windows',linux_host:'🐧 Linux',host:'💻 Host',
                };
                return (
                  <span key={role} className={`px-2 py-1 rounded-full text-xs font-semibold ${colorMap[role]}`}>
                    {labelMap[role]} ({count})
                  </span>
                );
              })}
            </div>

            {/* Filter */}
            <input
              type="text"
              placeholder="Filter by IP, hostname, OS, role…"
              value={assetFilter}
              onChange={e => setAssetFilter(e.target.value)}
              className="mb-3 w-full px-3 py-2 border rounded-md text-sm"
            />

            {/* Asset cards */}
            <div className="overflow-y-auto flex-1 space-y-3 pr-1">
              {assetResults
                .filter(a => {
                  if (!assetFilter) return true;
                  const q = assetFilter.toLowerCase();
                  return (
                    (a.ip_address||'').toLowerCase().includes(q) ||
                    (a.hostname||'').toLowerCase().includes(q) ||
                    (a.os_name||'').toLowerCase().includes(q) ||
                    (a.role||'').toLowerCase().includes(q) ||
                    (a.vendor||'').toLowerCase().includes(q)
                  );
                })
                .map((asset, idx) => (
                  <div key={idx} className="bg-white rounded-lg shadow-sm border border-gray-100 p-4">
                    {/* Header row */}
                    <div className="flex items-start justify-between mb-2">
                      <div>
                        <span className="font-bold text-gray-900 text-sm">{asset.ip_address}</span>
                        {asset.hostname && <span className="ml-2 text-xs text-gray-500">({asset.hostname})</span>}
                        {asset.mac_address && <span className="ml-2 text-xs text-gray-400">{asset.mac_address}</span>}
                      </div>
                      <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${{
                        network_device:'bg-orange-100 text-orange-800',
                        web_server:'bg-blue-100 text-blue-800',
                        container_host:'bg-purple-100 text-purple-800',
                        cloud_instance:'bg-sky-100 text-sky-800',
                        server:'bg-green-100 text-green-800',
                        windows_host:'bg-indigo-100 text-indigo-800',
                        linux_host:'bg-teal-100 text-teal-800',
                        host:'bg-gray-100 text-gray-600',
                      }[asset.role] || 'bg-gray-100 text-gray-600'}`}>
                        {asset.role?.replace(/_/g,' ')}
                      </span>
                    </div>

                    {/* OS / device type */}
                    {asset.os_name && (
                      <p className="text-xs text-gray-600 mb-2">
                        🖥 <strong>{asset.os_name}</strong>
                        {asset.os_accuracy ? ` (${asset.os_accuracy}% confidence)` : ''}
                        {asset.vendor ? ` · Vendor: ${asset.vendor}` : ''}
                      </p>
                    )}

                    {/* Open ports */}
                    {asset.open_ports?.length > 0 && (
                      <div className="mb-2">
                        <p className="text-xs font-medium text-gray-500 mb-1">Open Ports</p>
                        <div className="flex flex-wrap gap-1">
                          {asset.open_ports.map((p: any, pi: number) => (
                            <span key={pi} className="bg-gray-100 text-gray-700 text-xs px-2 py-0.5 rounded font-mono">
                              {p.port}/{p.protocol} {p.service && `(${p.service})`}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Web apps */}
                    {asset.web_apps?.length > 0 && (
                      <div className="mb-2">
                        <p className="text-xs font-medium text-gray-500 mb-1">🌍 Web Applications</p>
                        {asset.web_apps.map((w: any, wi: number) => (
                          <p key={wi} className="text-xs text-blue-600 font-mono">{w.url} {w.product && `· ${w.product} ${w.version}`}</p>
                        ))}
                      </div>
                    )}

                    {/* Containers */}
                    {asset.containers?.length > 0 && (
                      <div className="mb-2">
                        <p className="text-xs font-medium text-gray-500 mb-1">🐳 Containers</p>
                        {asset.containers.map((c: any, ci: number) => (
                          <span key={ci} className={`text-xs px-2 py-0.5 rounded mr-1 ${c.secured ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                            {c.type} :{c.port} {c.secured ? '(TLS)' : '⚠ Unsecured'}
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Cloud */}
                    {asset.cloud_instance && (
                      <p className="text-xs text-sky-600">☁ Cloud: {JSON.stringify(asset.cloud_instance)}</p>
                    )}
                  </div>
                ))}
            </div>
          </>
        ) : (
          /* ── Standard Terminal Console ── */
          <>
            <h2 className="text-xl font-bold mb-4">Execution Logs</h2>
            <div className="bg-gray-900 rounded-lg shadow flex-1 overflow-hidden flex flex-col font-mono text-sm">
              <div className="bg-gray-800 px-4 py-2 border-b border-gray-700 flex justify-between items-center text-gray-400">
                <span>Terminal</span>
                {isActivelyProcessing && <span className="flex h-3 w-3 relative"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span><span className="relative inline-flex rounded-full h-3 w-3 bg-green-500"></span></span>}
                {jobStatus === 'PAUSED' && <span className="h-3 w-3 rounded-full bg-yellow-500"></span>}
              </div>
              <div className="p-4 overflow-y-auto flex-1 text-green-400 space-y-1">
                {logs.length === 0 ? (
                  <p className="text-gray-500 italic">Waiting for logs...</p>
                ) : (
                  logs.map((log, i) => (
                    <div key={i} className="break-words">
                      <span className="text-gray-500 mr-3">[{log.timestamp}]</span>
                      <span className="text-gray-300">{log.message}</span>
                    </div>
                  ))
                )}
                <div ref={logsEndRef} />
              </div>
            </div>
          </>
        )}
      </div>
    </div>

    {/* History Section Moved */}
    <div className="w-full mt-4">
        {/* History Section */}
        <div>
          <div className="flex justify-between items-center mb-4 border-b pb-2">
            <div className="flex space-x-6">
              <button 
                className={`text-xl font-bold pb-2 ${!showArchived ? 'text-gray-900 border-b-2 border-blue-600' : 'text-gray-500 hover:text-gray-700'}`}
                onClick={() => setShowArchived(false)}
              >
                Recent Scans
              </button>
              <button 
                className={`text-xl font-bold pb-2 ${showArchived ? 'text-gray-900 border-b-2 border-blue-600' : 'text-gray-500 hover:text-gray-700'}`}
                onClick={() => setShowArchived(true)}
              >
                Archived Scans
              </button>
            </div>
          </div>
          <div className="bg-white rounded-lg shadow overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200 text-sm">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-3 text-left font-medium text-gray-500 align-top">
                    <div className="mb-1">Target</div>
                    <select 
                      className="border rounded px-2 py-1 text-xs w-full font-normal"
                      value={filterTarget}
                      onChange={(e) => setFilterTarget(e.target.value)}
                    >
                      <option value="">All</option>
                      {Array.from(new Set(sourceHistory.filter(job => ['COMPLETED', 'FAILED', 'STOPPED'].includes(job.status)).map(j => j.target))).filter(Boolean).sort().map((t: any, idx) => (
                        <option key={idx} value={t}>{t}</option>
                      ))}
                    </select>
                  </th>
                  <th className="px-4 py-3 text-left font-medium text-gray-500 align-top">
                    <div className="mb-1">Status</div>
                    <select 
                      className="border rounded px-2 py-1 text-xs w-full font-normal"
                      value={filterStatus}
                      onChange={(e) => setFilterStatus(e.target.value)}
                    >
                      <option value="">All</option>
                      {Array.from(new Set(sourceHistory.filter(job => ['COMPLETED', 'FAILED', 'STOPPED'].includes(job.status)).map(j => j.status))).filter(Boolean).sort().map((s: any, idx) => (
                        <option key={idx} value={s}>{s}</option>
                      ))}
                    </select>
                  </th>
                  <th className="px-4 py-3 text-left font-medium text-gray-500 align-top">
                    <div className="mb-1">Actions</div>
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredHistory.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="px-4 py-4 text-center text-gray-500">No matching scans found.</td>
                  </tr>
                ) : (
                  filteredHistory.map((job) => (
                    <tr key={job.scan_job_id} className="hover:bg-gray-50">
                      <td className="px-4 py-3 text-gray-900 truncate max-w-[150px]">{job.target}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                          ${job.status === 'COMPLETED' ? 'bg-green-100 text-green-800' : 
                            job.status === 'FAILED' ? 'bg-red-100 text-red-800' : 
                            job.status === 'STOPPED' ? 'bg-gray-100 text-gray-800' :
                            job.status === 'PAUSED' ? 'bg-yellow-100 text-yellow-800' :
                            'bg-blue-100 text-blue-800'}`}>
                          {job.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 flex space-x-3 items-center">
                        {job.status === 'COMPLETED' ? (
                          <>
                            <button 
                              onClick={() => loadHistoricalLogs(job.scan_job_id)}
                              className="text-blue-600 hover:text-blue-900 font-medium"
                            >
                              Logs
                            </button>
                            <span className="text-gray-300">|</span>
                            <button 
                              onClick={() => handleDownloadReport(job.scan_job_id, 'json')}
                              className="text-indigo-600 hover:text-indigo-900 font-medium flex items-center"
                            >
                              JSON
                            </button>
                            <button 
                              onClick={() => handleDownloadReport(job.scan_job_id, 'csv')}
                              className="text-emerald-600 hover:text-emerald-900 font-medium flex items-center"
                            >
                              CSV
                            </button>
                            {(job.scan_type === 'asset_discovery' || job.scan_type === 'full_scan') && (
                              <button 
                                onClick={() => fetchAssetResults(job.scan_job_id)}
                                className="text-blue-600 hover:text-blue-900 font-medium flex items-center"
                              >
                                🔍 Discovery
                              </button>
                            )}
                            {(job.scan_type === 'port_scan' || job.scan_type === 'full_scan') && (
                              <>
                                <span className="text-gray-300">|</span>
                                <button
                                  onClick={() => fetchPortScanResults(job.scan_job_id)}
                                  className="text-purple-600 hover:text-purple-900 font-medium flex items-center"
                                >
                                  🔌 Ports
                                </button>
                              </>
                            )}
                            {(job.scan_type === 'service_fingerprint' || job.scan_type === 'full_scan') && (
                              <>
                                <span className="text-gray-300">|</span>
                                <button
                                  onClick={() => fetchServiceResults(job.scan_job_id)}
                                  className="text-fuchsia-600 hover:text-fuchsia-900 font-medium flex items-center"
                                >
                                  🛠 Services
                                </button>
                              </>
                            )}
                            {(job.scan_type === 'enumeration' || job.scan_type === 'full_scan') && (
                              <>
                                <span className="text-gray-300">|</span>
                                <button
                                  onClick={() => fetchEnumResults(job.scan_job_id)}
                                  className="text-emerald-600 hover:text-emerald-900 font-medium flex items-center"
                                >
                                  📋 Enum Info
                                </button>
                              </>
                            )}
                            {(job.scan_type === 'vulnerability_scan' || job.scan_type === 'full_scan') && (
                              <>
                                <span className="text-gray-300">|</span>
                                <button
                                  onClick={() => fetchVulnScanResults(job.scan_job_id)}
                                  className="text-rose-600 hover:text-rose-900 font-medium flex items-center"
                                >
                                  🚨 Vulns
                                </button>
                              </>
                            )}
                            {(job.scan_type === 'authenticated' || job.scan_type === 'full_scan') && (
                              <>
                                <span className="text-gray-300">|</span>
                                <button 
                                  onClick={() => loadAuthScanResults(job.scan_job_id)}
                                  className="text-amber-600 hover:text-amber-900 font-medium flex items-center"
                                >
                                  🔑 Auth Scan
                                </button>
                              </>
                            )}
                            {(job.scan_type === 'risk_scoring' || job.scan_type === 'full_scan') && (
                              <>
                                <span className="text-gray-300">|</span>
                                <button 
                                  onClick={() => loadRiskScoringResults(job.scan_job_id)}
                                  className="text-orange-600 hover:text-orange-900 font-medium flex items-center"
                                >
                                  🎯 Risk Scores
                                </button>
                              </>
                            )}
                            {userRole === 'admin' && (
                              <>
                                <span className="text-gray-300">|</span>
                                {!showArchived ? (
                                  <button 
                                    onClick={() => handleArchiveScan(job.scan_job_id)}
                                    className="text-gray-600 hover:text-gray-900 font-medium flex items-center"
                                  >
                                    Archive
                                  </button>
                                ) : (
                                  <button 
                                    onClick={() => handleUnarchiveScan(job.scan_job_id)}
                                    className="text-blue-600 hover:text-blue-900 font-medium flex items-center"
                                  >
                                    Unarchive
                                  </button>
                                )}
                                <span className="text-gray-300">|</span>
                                <button 
                                  onClick={() => handleDeleteScan(job.scan_job_id)}
                                  className="text-red-600 hover:text-red-900 font-medium flex items-center"
                                >
                                  Delete
                                </button>
                              </>
                            )}
                          </>
                        ) : (
                          <>
                            <span className="text-gray-400 text-xs italic">Logs not available</span>
                            {userRole === 'admin' && (
                              <button 
                                onClick={() => handleDeleteScan(job.scan_job_id)}
                                className="ml-3 text-red-600 hover:text-red-900 font-medium flex items-center"
                              >
                                Delete
                              </button>
                            )}
                          </>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
