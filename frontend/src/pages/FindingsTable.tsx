import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';

export default function FindingsTable() {
  const [vulns, setVulns] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedFindings, setSelectedFindings] = useState<Set<number>>(new Set());
  
  const [filterSno, setFilterSno] = useState('');
  const [filterCveId, setFilterCveId] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterAsset, setFilterAsset] = useState('');

  useEffect(() => {
    const fetchVulns = async () => {
      try {
        const token = localStorage.getItem('token');
        const res = await fetch('http://localhost:8000/vulnerabilities/', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (res.ok) {
          const data = await res.json();
          setVulns(data.data || []);
        }
      } catch (err) {
        console.error("Failed to fetch vulnerabilities", err);
      } finally {
        setLoading(false);
      }
    };
    fetchVulns();
  }, []);

  const getSeverityColor = (severity: string) => {
    switch(severity?.toLowerCase()) {
      case 'critical': return 'bg-red-200 text-red-900';
      case 'high': return 'bg-orange-100 text-orange-800';
      case 'medium': return 'bg-yellow-100 text-yellow-800';
      case 'low': return 'bg-green-100 text-green-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const handleToggleSelect = (id: number) => {
    const newSelected = new Set(selectedFindings);
    if (newSelected.has(id)) {
      newSelected.delete(id);
    } else {
      newSelected.add(id);
    }
    setSelectedFindings(newSelected);
  };

  const filteredVulns = vulns.filter(v => {
    return (
      (filterSno === '' || `FIN-${v.id}` === filterSno) &&
      (filterCveId === '' || v.cve_id === filterCveId) &&
      (filterSeverity === '' || v.severity === filterSeverity) &&
      (filterAsset === '' || v.ip === filterAsset)
    );
  });

  const uniqueSnos = Array.from(new Set(vulns.map(v => `FIN-${v.id}`))).filter(Boolean).sort();
  const uniqueCves = Array.from(new Set(vulns.map(v => v.cve_id))).filter(Boolean).sort();
  const uniqueSeverities = Array.from(new Set(vulns.map(v => v.severity))).filter(Boolean).sort();
  const uniqueAssets = Array.from(new Set(vulns.map(v => v.ip))).filter(Boolean).sort();

  const [expandedIps, setExpandedIps] = useState<Record<string, boolean>>({});

  const toggleIp = (ip: string) => {
    setExpandedIps(prev => ({ ...prev, [ip]: !prev[ip] }));
  };

  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.checked) {
      setSelectedFindings(new Set(filteredVulns.map(v => v.id)));
    } else {
      setSelectedFindings(new Set());
    }
  };

  const handleGenerateReport = (format: 'json' | 'csv') => {
    if (selectedFindings.size === 0) {
      alert("Please select at least one finding to confirm and report.");
      return;
    }
    
    const confirmedData = vulns.filter(v => selectedFindings.has(v.id));
    
    let blob;
    if (format === 'json') {
      blob = new Blob([JSON.stringify({ findings: confirmedData }, null, 2)], { type: 'application/json' });
    } else {
      const headers = ["CVE ID", "Severity", "Risk Score", "Asset", "CWE", "CVSS Vector", "Published"];
      const rows = confirmedData.map(v => [
          v.cve_id || 'Unknown', 
          v.severity || 'Unknown', 
          v.risk_score || '0', 
          v.ip || 'Unknown',
          `"${(v.cwe || '').replace(/"/g, '""')}"`,
          `"${(v.cvss_vector || '').replace(/"/g, '""')}"`,
          v.published || 'Unknown'
      ]);
      const csvContent = [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
      blob = new Blob([csvContent], { type: 'text/csv' });
    }
    
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `confirmed_findings_report.${format}`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  };

  // Group the filtered vulnerabilities by Date, then by IP
  const groupedVulns = filteredVulns.reduce((acc: any, v: any) => {
    const date = v.scan_date ? v.scan_date.split('T')[0] : 'Unknown Date';
    const ip = v.ip || 'Unknown';
    if (!acc[date]) acc[date] = {};
    if (!acc[date][ip]) acc[date][ip] = [];
    acc[date][ip].push(v);
    return acc;
  }, {});

  return (
    <div className="p-8">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Vulnerability Findings</h1>
        <div className="flex space-x-4">
          <button 
            onClick={() => handleGenerateReport('json')}
            className="bg-indigo-600 text-white px-4 py-2 rounded shadow hover:bg-indigo-700"
          >
            Generate Report (JSON)
          </button>
          <button 
            onClick={() => handleGenerateReport('csv')}
            className="bg-emerald-600 text-white px-4 py-2 rounded shadow hover:bg-emerald-700"
          >
            Generate Report (CSV)
          </button>
        </div>
      </div>
      <div className="bg-white rounded-lg shadow overflow-hidden">
        {loading ? (
          <div className="p-4">Loading findings...</div>
        ) : (
          <table className="w-full text-left border-collapse">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 border-b text-sm font-semibold text-gray-700 align-top w-12">
                  <div className="mb-6">
                    <input 
                      type="checkbox" 
                      onChange={handleSelectAll}
                      checked={filteredVulns.length > 0 && Array.from(selectedFindings).every(id => filteredVulns.some(v => v.id === id)) && filteredVulns.length === selectedFindings.size}
                    />
                  </div>
                </th>
                <th className="px-6 py-3 border-b text-sm font-semibold text-gray-700 align-top">
                  <div className="mb-1">S.No</div>
                  <select 
                    className="border rounded px-2 py-1 text-xs w-full font-normal"
                    value={filterSno}
                    onChange={(e) => setFilterSno(e.target.value)}
                  >
                    <option value="">All</option>
                    {uniqueSnos.map((sno: any, idx) => (
                      <option key={idx} value={sno}>{sno}</option>
                    ))}
                  </select>
                </th>
                <th className="px-6 py-3 border-b text-sm font-semibold text-gray-700 align-top">
                  <div className="mb-1">CVE ID</div>
                  <select 
                    className="border rounded px-2 py-1 text-xs w-full font-normal"
                    value={filterCveId}
                    onChange={(e) => setFilterCveId(e.target.value)}
                  >
                    <option value="">All</option>
                    {uniqueCves.map((cve: any, idx) => (
                      <option key={idx} value={cve}>{cve}</option>
                    ))}
                  </select>
                </th>
                <th className="px-6 py-3 border-b text-sm font-semibold text-gray-700 align-top">
                  <div className="mb-1">Severity</div>
                  <select 
                    className="border rounded px-2 py-1 text-xs w-full font-normal"
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                  >
                    <option value="">All</option>
                    {uniqueSeverities.map((sev: any, idx) => (
                      <option key={idx} value={sev}>{sev}</option>
                    ))}
                  </select>
                </th>
                <th className="px-6 py-3 border-b text-sm font-semibold text-gray-700 align-top">
                  <div className="mb-1">Risk Score</div>
                </th>
                <th className="px-6 py-3 border-b text-sm font-semibold text-gray-700 align-top">
                  <div className="mb-1">Asset</div>
                  <select 
                    className="border rounded px-2 py-1 text-xs w-full font-normal"
                    value={filterAsset}
                    onChange={(e) => setFilterAsset(e.target.value)}
                  >
                    <option value="">All</option>
                    {uniqueAssets.map((asset: any, idx) => (
                      <option key={idx} value={asset}>{asset}</option>
                    ))}
                  </select>
                </th>
                <th className="px-6 py-3 border-b text-sm font-semibold text-gray-700 align-top">
                  <div className="mb-1">Actions</div>
                </th>
              </tr>
            </thead>
            <tbody>
              {Object.keys(groupedVulns).length === 0 ? (
                <tr><td colSpan={7} className="px-6 py-4 text-center">No vulnerabilities found.</td></tr>
              ) : (
                Object.keys(groupedVulns).sort((a,b) => b.localeCompare(a)).map(date => {
                  const dateKey = `date:${date}`;
                  const isDateExpanded = !!expandedIps[dateKey];
                  
                  // Calculate total findings for this date across all IPs
                  const totalDateFindings = Object.values(groupedVulns[date]).reduce((sum: any, arr: any) => sum + arr.length, 0);

                  return (
                    <React.Fragment key={dateKey}>
                      <tr 
                        className="bg-gray-200 border-b cursor-pointer hover:bg-gray-300 transition-colors"
                        onClick={() => toggleIp(dateKey)}
                      >
                        <td colSpan={7} className="px-6 py-3 font-bold text-gray-900">
                          <div className="flex items-center gap-2">
                            <svg 
                              className={`w-5 h-5 transform transition-transform ${isDateExpanded ? 'rotate-90' : ''}`} 
                              fill="none" viewBox="0 0 24 24" stroke="currentColor"
                            >
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                            </svg>
                            Date: {date} <span className="text-sm font-normal text-gray-600 ml-2">({totalDateFindings} findings)</span>
                          </div>
                        </td>
                      </tr>
                      {isDateExpanded && Object.keys(groupedVulns[date]).sort().map(ip => {
                        const ipKey = `ip:${date}:${ip}`;
                        const isIpExpanded = !!expandedIps[ipKey];
                        const findings = groupedVulns[date][ip];
                        return (
                          <React.Fragment key={ipKey}>
                            <tr 
                              className="bg-gray-50 border-b cursor-pointer hover:bg-gray-100 transition-colors"
                              onClick={() => toggleIp(ipKey)}
                            >
                              <td colSpan={7} className="px-10 py-2 font-semibold text-gray-800">
                                <div className="flex items-center gap-2">
                                  <svg 
                                    className={`w-4 h-4 transform transition-transform ${isIpExpanded ? 'rotate-90' : ''}`} 
                                    fill="none" viewBox="0 0 24 24" stroke="currentColor"
                                  >
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                  </svg>
                                  Asset: {ip} <span className="text-xs font-normal text-gray-500 ml-2">({findings.length} findings)</span>
                                </div>
                              </td>
                            </tr>
                            {isIpExpanded && findings.map((v: any, i: number) => (
                              <tr key={v.id} className={`border-b hover:bg-gray-50 ${selectedFindings.has(v.id) ? 'bg-blue-50' : ''}`}>
                                <td className="px-6 py-4">
                                  <input 
                                    type="checkbox" 
                                    checked={selectedFindings.has(v.id)}
                                    onChange={() => handleToggleSelect(v.id)}
                                  />
                                </td>
                                <td className="px-6 py-4 font-mono text-gray-500 font-semibold text-xs">
                                  FIN-{v.id}
                                </td>
                                <td className="px-6 py-4 font-mono text-blue-600">
                                  {v.cve_id ? (
                                    <Link to={`/findings/${v.id}`} className="hover:underline font-bold">
                                      {v.cve_id}
                                    </Link>
                                  ) : (
                                    'Unknown CVE'
                                  )}
                                </td>
                                <td className="px-6 py-4"><span className={`px-2 py-1 rounded-full text-xs ${getSeverityColor(v.severity)}`}>{v.severity || 'Unknown'}</span></td>
                                <td className="px-6 py-4">{v.risk_score}</td>
                                <td className="px-6 py-4">{v.ip}</td>
                                <td className="px-6 py-4"><Link to={`/remediation?vulnId=${v.id}`} className="text-blue-600 hover:underline">Remediate</Link></td>
                              </tr>
                            ))}
                          </React.Fragment>
                        );
                      })}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
