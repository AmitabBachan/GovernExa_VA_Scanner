import { useState, useEffect } from 'react';
import { Logo } from '../components/Logo';

export default function Reporting() {
  const [history, setHistory] = useState<any[]>([]);
  const [selectedScans, setSelectedScans] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [reportData, setReportData] = useState<any>(null);
  
  const [activeTab, setActiveTab] = useState<'collate' | 'saved'>('collate');
  const [savedReports, setSavedReports] = useState<any[]>([]);
  const isAdmin = localStorage.getItem('role') === 'admin';

  useEffect(() => {
    fetchHistory();
    fetchSavedReports();
  }, []);

  const fetchHistory = async () => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch('http://localhost:8000/scan/history', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setHistory(data.filter((j: any) => j.status === 'COMPLETED'));
      }
    } catch (err) {
      console.error("Error fetching history", err);
    } finally {
      setLoading(false);
    }
  };

  const fetchSavedReports = async () => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch('http://localhost:8000/reports/saved', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setSavedReports(data);
      }
    } catch (err) {
      console.error("Error fetching saved reports", err);
    }
  };

  const handleToggleSelect = (id: string) => {
    const newSelected = new Set(selectedScans);
    if (newSelected.has(id)) {
      newSelected.delete(id);
    } else {
      newSelected.add(id);
    }
    setSelectedScans(newSelected);
  };

  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.checked) {
      setSelectedScans(new Set(history.map(v => v.scan_job_id)));
    } else {
      setSelectedScans(new Set());
    }
  };

  const saveReportToDatabase = async () => {
    if (selectedScans.size === 0) {
      alert("Please select at least one scan to save.");
      return;
    }
    const name = prompt("Enter a name for this saved report:", `Report - ${new Date().toLocaleDateString()}`);
    if (!name) return;

    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`http://localhost:8000/reports/?name=${encodeURIComponent(name)}&scan_job_ids=${encodeURIComponent(Array.from(selectedScans).join(','))}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        alert("Report saved successfully!");
        fetchSavedReports();
        setActiveTab('saved');
      } else {
        alert("Failed to save report. You might not have permission.");
      }
    } catch (err) {
      console.error("Error saving report", err);
    }
  };

  const deleteSavedReport = async (id: number) => {
    if (!confirm("Are you sure you want to delete this report?")) return;
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`http://localhost:8000/reports/${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        fetchSavedReports();
      } else {
        alert("Failed to delete report. You might not have permission.");
      }
    } catch (err) {
      console.error("Error deleting report", err);
    }
  };

  const modifySavedReport = async (id: number, currentName: string) => {
    const newName = prompt("Enter new name for the report:", currentName);
    if (!newName) return;
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`http://localhost:8000/reports/${id}?name=${encodeURIComponent(newName)}`, {
        method: 'PUT',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        fetchSavedReports();
      } else {
        alert("Failed to modify report. You might not have permission.");
      }
    } catch (err) {
      console.error("Error modifying report", err);
    }
  };

  const generateReportFromSaved = (scans: string) => {
    setSelectedScans(new Set(scans.split(',')));
    setActiveTab('collate');
  };

  const generateReport = async (format: 'json' | 'csv' | 'pdf' | 'html' | 'docx' | 'xlsx') => {
    if (selectedScans.size === 0) {
      alert("Please select at least one scan to report on.");
      return;
    }
    
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`http://localhost:8000/reports/export/${format}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ scan_job_ids: Array.from(selectedScans) })
      });
      
      if (!response.ok) throw new Error("Failed to generate report");
      
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `govern_exa_report_${new Date().getTime()}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
    } catch (err) {
      alert("Error generating report.");
      console.error(err);
    }
  };

  if (reportData) {
    return (
        <div className="bg-white p-12 text-black print-only-container">
            <div className="flex items-center justify-between border-b pb-6 mb-8">
                <Logo variant="dark" stacked={false} className="h-16" />
                <h1 className="text-3xl font-bold text-gray-800">Security Report</h1>
            </div>
            
            <div className="mb-12">
                <h2 className="text-2xl font-semibold mb-4">Executive Summary</h2>
                <div className="grid grid-cols-2 gap-8">
                    <div className="bg-gray-100 p-6 rounded">
                        <p className="text-sm text-gray-600 uppercase font-bold tracking-wider">Total Discovered Devices</p>
                        <p className="text-5xl font-bold mt-2 text-blue-600">{reportData.summary.total_devices_discovered}</p>
                    </div>
                    <div className="bg-gray-100 p-6 rounded">
                        <p className="text-sm text-gray-600 uppercase font-bold tracking-wider">Total Vulnerabilities Found</p>
                        <p className="text-5xl font-bold mt-2 text-red-600">{reportData.summary.total_vulnerabilities_found}</p>
                    </div>
                </div>
            </div>

            <div className="mb-12">
                <h2 className="text-2xl font-semibold mb-4 border-b pb-2">Discovered Assets</h2>
                <table className="w-full text-left border-collapse">
                    <thead>
                        <tr className="bg-gray-200">
                            <th className="p-3 border">IP Address</th>
                            <th className="p-3 border">Operating System</th>
                        </tr>
                    </thead>
                    <tbody>
                        {reportData.devices.map((d: any, i: number) => (
                            <tr key={i}>
                                <td className="p-3 border font-mono">{d.ip_address}</td>
                                <td className="p-3 border">{d.os_name || 'Unknown'}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            <div className="mb-12">
                <h2 className="text-2xl font-semibold mb-4 border-b pb-2">Technical Findings</h2>
                <table className="w-full text-left border-collapse">
                    <thead>
                        <tr className="bg-gray-200">
                            <th className="p-3 border">Severity</th>
                            <th className="p-3 border">Asset</th>
                            <th className="p-3 border">CVE ID</th>
                        </tr>
                    </thead>
                    <tbody>
                        {reportData.findings.map((f: any, i: number) => (
                            <tr key={i}>
                                <td className="p-3 border font-bold">{f.severity}</td>
                                <td className="p-3 border font-mono">{f.affected_ip}</td>
                                <td className="p-3 border font-mono">{f.cve_id}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
  }

  return (
    <div className="p-8">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Reporting</h1>
      </div>

      <div className="flex border-b mb-6">
        <button 
          className={`py-2 px-4 font-semibold ${activeTab === 'collate' ? 'border-b-2 border-blue-600 text-blue-600' : 'text-gray-500 hover:text-gray-700'}`}
          onClick={() => setActiveTab('collate')}
        >
          New Collation
        </button>
        <button 
          className={`py-2 px-4 font-semibold ${activeTab === 'saved' ? 'border-b-2 border-blue-600 text-blue-600' : 'text-gray-500 hover:text-gray-700'}`}
          onClick={() => setActiveTab('saved')}
        >
          Saved Reports
        </button>
      </div>
      
      {activeTab === 'collate' && (
        <>
          <div className="flex justify-between items-center mb-6 bg-gray-50 p-4 rounded-lg shadow-sm border">
            <div>
              <p className="text-gray-800 font-medium">Select scans to report on ({selectedScans.size} selected)</p>
            </div>
            <div className="flex space-x-3">
              {isAdmin && (
                <button 
                  onClick={saveReportToDatabase}
                  className="bg-gray-800 text-white px-4 py-2 rounded shadow hover:bg-gray-900 text-sm font-semibold"
                >
                  Save Configuration
                </button>
              )}
              <select 
                id="exportFormat" 
                className="border p-2 rounded text-sm bg-white"
              >
                <option value="pdf">PDF (WeasyPrint)</option>
                <option value="html">HTML</option>
                <option value="docx">Word (DOCX)</option>
                <option value="xlsx">Excel (XLSX)</option>
                <option value="csv">CSV</option>
                <option value="json">JSON</option>
              </select>
              <button 
                onClick={() => generateReport((document.getElementById('exportFormat') as HTMLSelectElement).value as any)}
                className="bg-blue-600 text-white px-4 py-2 rounded shadow hover:bg-blue-700 text-sm font-semibold"
              >
                Generate Export
              </button>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow overflow-hidden">
            {loading ? (
              <div className="p-4">Loading scan history...</div>
            ) : (
              <table className="min-w-full text-left border-collapse">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 border-b text-sm font-semibold text-gray-700 w-12">
                      <input 
                        type="checkbox" 
                        onChange={handleSelectAll}
                        checked={history.length > 0 && selectedScans.size === history.length}
                      />
                    </th>
                    <th className="px-6 py-3 border-b text-sm font-semibold text-gray-700">Scan Job ID</th>
                    <th className="px-6 py-3 border-b text-sm font-semibold text-gray-700">Target</th>
                    <th className="px-6 py-3 border-b text-sm font-semibold text-gray-700">Scan Type</th>
                    <th className="px-6 py-3 border-b text-sm font-semibold text-gray-700">Completed At</th>
                  </tr>
                </thead>
                <tbody>
                  {history.length === 0 ? (
                    <tr><td colSpan={5} className="px-6 py-4 text-center">No completed scans found.</td></tr>
                  ) : (
                    history.map((job, i) => (
                      <tr key={i} className={`border-b hover:bg-gray-50 ${selectedScans.has(job.scan_job_id) ? 'bg-blue-50' : ''}`}>
                        <td className="px-6 py-4">
                          <input 
                            type="checkbox" 
                            checked={selectedScans.has(job.scan_job_id)}
                            onChange={() => handleToggleSelect(job.scan_job_id)}
                          />
                        </td>
                        <td className="px-6 py-4 font-mono text-sm text-gray-600">{job.scan_job_id.substring(0, 8)}...</td>
                        <td className="px-6 py-4 font-mono">{job.target}</td>
                        <td className="px-6 py-4">{job.scan_type}</td>
                        <td className="px-6 py-4 text-sm text-gray-600">{new Date(job.completed_at).toLocaleString()}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}

      {activeTab === 'saved' && (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          {savedReports.length === 0 ? (
            <div className="p-6 text-center text-gray-500">No saved reports found. Create one from the New Collation tab.</div>
          ) : (
            <table className="min-w-full text-left border-collapse">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 border-b text-sm font-semibold text-gray-700">Report Name</th>
                  <th className="px-6 py-3 border-b text-sm font-semibold text-gray-700">Created At</th>
                  <th className="px-6 py-3 border-b text-sm font-semibold text-gray-700">Actions</th>
                </tr>
              </thead>
              <tbody>
                {savedReports.map((r, i) => (
                  <tr key={i} className="border-b hover:bg-gray-50">
                    <td className="px-6 py-4 font-semibold text-gray-800">{r.name}</td>
                    <td className="px-6 py-4 text-sm text-gray-600">{new Date(r.created_at).toLocaleString()}</td>
                    <td className="px-6 py-4 flex gap-3">
                      <button 
                        onClick={() => generateReportFromSaved(r.scans)}
                        className="text-blue-600 font-semibold hover:underline"
                      >
                        Load
                      </button>
                      {isAdmin && (
                        <>
                          <button 
                            onClick={() => modifySavedReport(r.id, r.name)}
                            className="text-gray-600 font-semibold hover:underline"
                          >
                            Modify
                          </button>
                          <button 
                            onClick={() => deleteSavedReport(r.id)}
                            className="text-red-600 font-semibold hover:underline"
                          >
                            Delete
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
