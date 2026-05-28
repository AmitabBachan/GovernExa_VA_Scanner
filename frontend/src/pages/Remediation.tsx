import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';

export default function Remediation() {
  const [vulns, setVulns] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  
  const location = useLocation();
  const queryParams = new URLSearchParams(location.search);
  const initialVulnId = queryParams.get('vulnId');
  const [filterVulnId, setFilterVulnId] = useState(initialVulnId || '');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterIp, setFilterIp] = useState('');
  const [filterStatus, setFilterStatus] = useState('');

  useEffect(() => {
    // If the URL changes (e.g. user navigates here again), update the filter
    const newVulnId = new URLSearchParams(location.search).get('vulnId');
    if (newVulnId) {
      setFilterVulnId(newVulnId);
      // Auto-expand the incoming finding card if navigating from FindingsTable
      setExpandedCards(prev => ({ ...prev, [Number(newVulnId)]: true }));
    }
  }, [location.search]);

  useEffect(() => {
    const fetchVulns = async () => {
      try {
        const token = localStorage.getItem('token');
        const res = await fetch('http://localhost:8000/vulnerabilities/', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (res.ok) {
          const data = await res.json();
          setVulns(data.data);
          
          // Initial auto-expand if query param was present on first load
          if (initialVulnId) {
             setExpandedCards(prev => ({ ...prev, [Number(initialVulnId)]: true }));
          }
        }
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    fetchVulns();
  }, []);

  const [expandedCards, setExpandedCards] = useState<Record<number, boolean>>({});

  const toggleExpand = (id: number) => {
    setExpandedCards(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const handleStatusChange = async (vulnId: number, newStatus: string) => {
    const vuln = vulns.find(v => v.id === vulnId);
    if (newStatus === 'Closed' && (!vuln?.reason || vuln.reason.trim() === '')) {
      alert("A Reason must be provided before marking this vulnerability as Closed.");
      // The select will automatically revert to its old value since we aren't updating state
      return;
    }

    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`http://localhost:8000/vulnerabilities/${vulnId}/status`, {
        method: 'PATCH',
        headers: { 
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ status: newStatus })
      });
      if (res.ok) {
        setVulns(vulns.map(v => v.id === vulnId ? { ...v, status: newStatus } : v));
      } else {
        const errorData = await res.json();
        alert(`Failed to update status: ${errorData.detail || 'Unknown error'}`);
      }
    } catch (err) {
      console.error(err);
      alert("Error updating status");
    }
  };

  const handleReasonChange = async (vulnId: number, newReason: string) => {
    const vuln = vulns.find(v => v.id === vulnId);
    if (vuln?.status === 'Closed' && newReason.trim() === '') {
      alert("Cannot clear the reason while the vulnerability is marked as Closed. Please change the status first.");
      // Optionally we could force re-render to revert input, but for now we just block save
      return;
    }

    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`http://localhost:8000/vulnerabilities/${vulnId}/reason`, {
        method: 'PATCH',
        headers: { 
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ reason: newReason })
      });
      if (res.ok) {
        setVulns(vulns.map(v => v.id === vulnId ? { ...v, reason: newReason } : v));
      } else {
        const errorData = await res.json();
        alert(`Failed to update reason: ${errorData.detail || 'Unknown error'}`);
      }
    } catch (err) {
      console.error(err);
      alert("Error updating reason");
    }
  };

  const [ticketStatus, setTicketStatus] = useState<Record<number, 'idle' | 'generating' | 'success' | 'error'>>({});

  const handleGenerateTicket = async (vulnId: number) => {
    setTicketStatus(prev => ({ ...prev, [vulnId]: 'generating' }));
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`http://localhost:8000/vulnerabilities/${vulnId}/ticket`, {
        method: 'POST',
        headers: { 
          'Authorization': `Bearer ${token}`
        }
      });
      if (res.ok) {
        setTicketStatus(prev => ({ ...prev, [vulnId]: 'success' }));
        setTimeout(() => setTicketStatus(prev => ({ ...prev, [vulnId]: 'idle' })), 3000);
      } else {
        const errorData = await res.json();
        alert(`Failed to generate ticket: ${errorData.detail || 'Unknown error'}`);
        setTicketStatus(prev => ({ ...prev, [vulnId]: 'error' }));
        setTimeout(() => setTicketStatus(prev => ({ ...prev, [vulnId]: 'idle' })), 3000);
      }
    } catch (err) {
      console.error(err);
      alert("Network error generating ticket");
      setTicketStatus(prev => ({ ...prev, [vulnId]: 'error' }));
      setTimeout(() => setTicketStatus(prev => ({ ...prev, [vulnId]: 'idle' })), 3000);
    }
  };

  const displayVulns = vulns.filter(v => {
    const matchId = filterVulnId === '' || v.id.toString() === filterVulnId;
    const matchSev = filterSeverity === '' || v.severity === filterSeverity;
    const matchIp = filterIp === '' || v.ip === filterIp;
    const matchStatus = filterStatus === '' || (v.status || 'Open') === filterStatus;
    return matchId && matchSev && matchIp && matchStatus;
  });

  const uniqueVulns = Array.from(new Set(vulns.map(v => v.id))).sort((a,b) => a - b);
  const uniqueSeverities = Array.from(new Set(vulns.map(v => v.severity))).filter(Boolean);
  const uniqueIps = Array.from(new Set(vulns.map(v => v.ip))).filter(Boolean);
  const uniqueStatuses = Array.from(new Set(vulns.map(v => v.status || "Open"))).filter(Boolean);

  const handleGenerateReport = () => {
    if (displayVulns.length === 0) {
      alert("No data to report.");
      return;
    }
    const reportData = displayVulns.map(v => ({
      CVE: v.cve_id,
      Status: v.status || "Open",
      Title: v.title,
      Published: v.published,
      Updated: v.updated,
      Description: v.description,
      CWE: v.cwe,
      CVSS_Score: v.cvss_score !== 'N/A' ? v.cvss_score : v.risk_score,
      Severity: v.severity,
      AffectedProducts: v.affected_products,
      References: v.all_references || v.reference
    }));
    
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `remediation_report_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  };

  return (
    <div className="p-8 max-w-6xl mx-auto">
      <div className="flex flex-col gap-6 mb-6">
        <div className="flex justify-between items-center">
          <h1 className="text-2xl font-bold">Remediation Action Plan</h1>
          <button 
            onClick={handleGenerateReport}
            className="bg-indigo-600 text-white px-4 py-2 rounded shadow hover:bg-indigo-700 font-semibold text-sm"
          >
            Download Remediation Report
          </button>
        </div>
        
        {/* Filters */}
        <div className="flex flex-wrap items-center gap-4 bg-white p-4 rounded shadow-sm border border-gray-100">
          <div className="flex items-center gap-2">
            <label className="text-sm font-semibold text-gray-600">Finding:</label>
            <select 
              className="border rounded px-3 py-1.5 text-sm bg-white font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500"
              value={filterVulnId}
              onChange={(e) => setFilterVulnId(e.target.value)}
            >
              <option value="">All</option>
              {uniqueVulns.map(id => (
                <option key={id} value={id.toString()}>FIN-{id}</option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-2">
            <label className="text-sm font-semibold text-gray-600">Severity:</label>
            <select 
              className="border rounded px-3 py-1.5 text-sm bg-white font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500"
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
            >
              <option value="">All</option>
              {uniqueSeverities.map(sev => (
                <option key={sev} value={sev}>{sev}</option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-2">
            <label className="text-sm font-semibold text-gray-600">Asset No:</label>
            <select 
              className="border rounded px-3 py-1.5 text-sm bg-white font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500"
              value={filterIp}
              onChange={(e) => setFilterIp(e.target.value)}
            >
              <option value="">All</option>
              {uniqueIps.map(ip => (
                <option key={ip} value={ip}>{ip}</option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-2">
            <label className="text-sm font-semibold text-gray-600">Status:</label>
            <select 
              className="border rounded px-3 py-1.5 text-sm bg-white font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500"
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
            >
              <option value="">All</option>
              {uniqueStatuses.map(status => (
                <option key={status} value={status}>{status}</option>
              ))}
            </select>
          </div>
        </div>
      </div>
      
      {loading ? (
        <p>Loading remediations...</p>
      ) : displayVulns.length === 0 ? (
        <div className="p-6 bg-white rounded-lg shadow text-gray-500">No vulnerabilities found requiring remediation.</div>
      ) : (
        <div className="flex flex-col gap-6">
          {displayVulns.map((vuln) => {
            const year = vuln.cve_id ? vuln.cve_id.split('-')[1] : 'Unknown';
            const cweId = vuln.cwe && vuln.cwe.includes(':') ? vuln.cwe.split(':')[0] : (vuln.cwe || 'Unknown');
            const cweDesc = vuln.cwe && vuln.cwe.includes(':') ? vuln.cwe.split(':')[1].trim() : '';
            const isExpanded = !!expandedCards[vuln.id];
            
            return (
              <div key={vuln.id} className="bg-[#111827] rounded-xl shadow-xl overflow-hidden border border-gray-800 transition-all duration-300">
                {/* Header (Always Visible) */}
                <div className="p-6 bg-gradient-to-r from-[#1e293b] to-[#0f172a] border-b border-gray-800">
                  <div className="flex justify-between items-start cursor-pointer" onClick={() => toggleExpand(vuln.id)}>
                    <div className="flex gap-4">
                      <div className="flex flex-col items-center justify-center w-16 h-16 bg-gray-900 rounded-lg border border-gray-700 shadow-inner">
                        <span className="text-xs text-gray-400 font-mono">FIN-{vuln.id}</span>
                        <span className="text-sm font-bold text-gray-200">{year}</span>
                      </div>
                      <div>
                        <div className="flex items-center gap-3 mb-2">
                          <span className={`px-3 py-1 rounded-full text-xs font-bold shadow-sm border
                            ${vuln.severity === 'CRITICAL' ? 'bg-red-900/50 text-red-400 border-red-500/30' : 
                              vuln.severity === 'HIGH' ? 'bg-orange-900/50 text-orange-400 border-orange-500/30' : 
                              vuln.severity === 'MEDIUM' ? 'bg-yellow-900/50 text-yellow-400 border-yellow-500/30' : 
                              'bg-green-900/50 text-green-400 border-green-500/30'}`}>
                            {vuln.severity}
                          </span>
                          <span className="text-xl font-mono text-[#3b82f6] font-semibold">{vuln.cve_id}</span>
                        </div>
                        <h2 className="text-lg font-bold text-gray-100 max-w-2xl">{vuln.title !== 'Title not available' ? vuln.title : (cweDesc || 'Vulnerability Details')}</h2>
                      </div>
                    </div>
                    <div className="flex flex-col items-end gap-2" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center gap-4">
                          <div className="flex flex-col text-right mr-4">
                            <span className="text-xs text-gray-500 uppercase tracking-wider font-semibold">Asset No (IP)</span>
                            <span className="text-sm text-gray-300 font-mono">{vuln.ip || 'N/A'}</span>
                          </div>
                          <div className="flex flex-col text-right mr-4">
                            <span className="text-xs text-gray-500 uppercase tracking-wider font-semibold">Scan Date</span>
                            <span className="text-sm text-gray-300 font-mono">{vuln.scan_date ? new Date(vuln.scan_date).toLocaleString() : 'N/A'}</span>
                          </div>
                          <select 
                            value={vuln.status || "Open"}
                            onChange={(e) => handleStatusChange(vuln.id, e.target.value)}
                            className={`font-semibold rounded-full px-3 py-1.5 text-xs shadow-sm focus:outline-none focus:ring-2 focus:ring-offset-1 focus:ring-offset-[#111827] focus:ring-indigo-500 cursor-pointer transition-colors duration-200
                              ${(vuln.status || "Open") === "Open" ? "bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30" : 
                                (vuln.status === "InProcess" ? "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 hover:bg-yellow-500/30" : 
                                 "bg-green-500/20 text-green-400 border border-green-500/30 hover:bg-green-500/30")
                              }`}
                          >
                            <option value="Open" className="bg-[#1e293b] text-red-400">Open</option>
                            <option value="InProcess" className="bg-[#1e293b] text-yellow-400">InProcess</option>
                            <option value="Closed" className="bg-[#1e293b] text-green-400">Closed</option>
                          </select>
                          <button 
                            onClick={() => toggleExpand(vuln.id)}
                            className="text-gray-400 hover:text-white transition-colors bg-gray-800 p-2 rounded-full border border-gray-700"
                          >
                            <svg className={`w-5 h-5 transform transition-transform duration-300 ${expandedCards[vuln.id] ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                            </svg>
                          </button>
                        </div>
                    </div>
                  </div>
                </div>

                {/* Expandable Body */}
                {isExpanded && (
                  <div className="p-8 pt-4 border-t border-gray-800">
                    {/* Description */}
                    <div className="mb-8">
                      <h3 className="text-xl font-bold text-white mb-4 border-l-4 border-blue-500 pl-3">Description</h3>
                      <p className="text-[#94a3b8] leading-relaxed">
                        {vuln.description}
                      </p>
                    </div>

                    {/* CWE and Assigner Cards */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                      <div className="bg-[#161f33] border border-gray-700 rounded-lg p-5">
                        <p className="text-xs font-bold text-gray-500 mb-2 uppercase tracking-wide">CWE (Problem Type)</p>
                        <h4 className="text-xl font-bold text-white">{cweId}</h4>
                        {cweDesc && <p className="text-sm text-[#94a3b8] mt-1">{cweDesc}</p>}
                      </div>
                      <div className="bg-[#161f33] border border-gray-700 rounded-lg p-5">
                        <p className="text-xs font-bold text-gray-500 mb-2 uppercase tracking-wide">Assigner</p>
                        <h4 className="text-xl font-bold text-white">{vuln.cna_name}</h4>
                      </div>
                    </div>

                    {/* Affected Products Table */}
                    <div className="mb-8">
                      <h3 className="text-xl font-bold text-white mb-4 border-l-4 border-blue-500 pl-3">Affected Products</h3>
                      <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse text-sm">
                          <thead>
                            <tr className="border-b border-gray-700">
                              <th className="py-4 font-bold text-[#cbd5e1] w-1/4">Vendor</th>
                              <th className="py-4 font-bold text-[#cbd5e1] w-1/2">Product</th>
                              <th className="py-4 font-bold text-[#cbd5e1] w-1/4">Versions Affected</th>
                            </tr>
                          </thead>
                          <tbody>
                            {vuln.affected_products && vuln.affected_products.length > 0 ? (
                              vuln.affected_products.map((prod: any, idx: number) => (
                                <tr key={idx} className="border-b border-gray-800 last:border-b-0">
                                  <td className="py-4 text-white font-semibold">{prod.vendor}</td>
                                  <td className="py-4 text-white font-semibold">{prod.product}</td>
                                  <td className="py-4 text-white font-semibold flex items-center gap-2">
                                    {prod.version}
                                    {prod.status === 'unaffected' ? (
                                      <span className="text-[#ef4444] text-xs">[unaffected]</span>
                                    ) : (
                                      <span className="text-gray-400 text-xs">[{prod.status}]</span>
                                    )}
                                  </td>
                                </tr>
                              ))
                            ) : (
                              <tr>
                                <td colSpan={3} className="py-4 text-gray-500 italic">No specific products listed.</td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>

                    {/* References */}
                    <div className="mb-8">
                      <h3 className="text-xl font-bold text-white mb-4 border-l-4 border-blue-500 pl-3">References</h3>
                      <ul className="space-y-3">
                        {vuln.all_references && vuln.all_references.length > 0 ? (
                          vuln.all_references.map((ref: any, idx: number) => (
                            <li key={idx}>
                              <a href={ref.url} target="_blank" rel="noreferrer" className="text-[#3b82f6] hover:underline flex items-center gap-2 font-medium text-sm">
                                {ref.url} <span className="text-xs">&#8599;</span>
                              </a>
                            </li>
                          ))
                        ) : (
                          vuln.reference && (
                            <li>
                              <a href={vuln.reference} target="_blank" rel="noreferrer" className="text-[#3b82f6] hover:underline flex items-center gap-2 font-medium text-sm">
                                {vuln.reference} <span className="text-xs">&#8599;</span>
                              </a>
                            </li>
                          )
                        )}
                      </ul>
                    </div>

                    {/* Remediation & Mitigation */}
                    <div>
                      <h3 className="text-xl font-bold text-white mb-4 border-l-4 border-emerald-500 pl-3">Official Remediation & Mitigation</h3>
                      
                      {vuln.solution && (
                        <div className="bg-[#161f33] border border-emerald-700/50 rounded-lg p-6 mb-4 shadow-lg shadow-emerald-900/10">
                          <h4 className="font-bold text-emerald-400 mb-3 text-lg flex items-center gap-2">
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            Official Solution
                          </h4>
                          <p className="text-[#94a3b8] text-sm leading-relaxed whitespace-pre-wrap">
                            {vuln.solution}
                          </p>
                        </div>
                      )}
                      
                      {vuln.workaround && (
                        <div className="bg-[#161f33] border border-amber-700/50 rounded-lg p-6 mb-4 shadow-lg shadow-amber-900/10">
                          <h4 className="font-bold text-amber-400 mb-3 text-lg flex items-center gap-2">
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                            </svg>
                            Workaround
                          </h4>
                          <p className="text-[#94a3b8] text-sm leading-relaxed whitespace-pre-wrap">
                            {vuln.workaround}
                          </p>
                        </div>
                      )}

                      {!vuln.solution && !vuln.workaround && (
                        <div className="bg-[#161f33] border border-gray-700 rounded-lg p-6 mb-4">
                          <h4 className="font-bold text-white mb-2 text-lg">General Patch Management & Updates</h4>
                          <p className="text-[#94a3b8] text-sm leading-relaxed">
                            Always prioritize applying the official patches provided by the vendor. For automated updates, ensure your patch management tools are configured to deploy critical security updates promptly. You can reference <button 
                              onClick={(e) => {
                                e.preventDefault();
                                if (window.confirm(`You are about to be redirected to an external website (CISA KEV Catalog) to view details for ${vuln.cve_id}. Do you want to continue?`)) {
                                  window.open(`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${vuln.cve_id}`, '_blank');
                                }
                              }}
                              className="text-[#3b82f6] hover:underline cursor-pointer bg-transparent border-none p-0 inline font-medium"
                            >
                              CISA's KEV Catalog
                            </button> for prioritizing high-risk vulnerabilities.
                          </p>
                        </div>
                      )}
                    </div>
                    
                    {/* Actions */}
                    <div className="mt-8 pt-6 border-t border-gray-800 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                      <div className="w-full md:w-2/3 flex items-center gap-3">
                        <label className="text-sm font-semibold text-gray-400 whitespace-nowrap">Reason:</label>
                        <input 
                          type="text" 
                          placeholder="Provide a reason for the current status..."
                          defaultValue={vuln.reason || ''}
                          onBlur={(e) => handleReasonChange(vuln.id, e.target.value)}
                          className="w-full bg-[#1e293b] text-white text-sm px-4 py-2 rounded border border-gray-700 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors"
                        />
                      </div>
                      <button 
                        onClick={() => handleGenerateTicket(vuln.id)}
                        disabled={ticketStatus[vuln.id] === 'generating'}
                        className={`px-6 py-2 text-white rounded font-semibold text-sm transition-colors whitespace-nowrap shadow-lg ${
                          ticketStatus[vuln.id] === 'success' ? 'bg-emerald-600 shadow-emerald-500/20' : 
                          ticketStatus[vuln.id] === 'error' ? 'bg-red-600 shadow-red-500/20' : 
                          ticketStatus[vuln.id] === 'generating' ? 'bg-gray-600 cursor-not-allowed' :
                          'bg-blue-600 hover:bg-blue-700 shadow-blue-500/20'
                        }`}
                      >
                        {ticketStatus[vuln.id] === 'success' ? '✓ Ticket Generated' : 
                         ticketStatus[vuln.id] === 'generating' ? 'Sending...' : 
                         ticketStatus[vuln.id] === 'error' ? 'Failed!' : 
                         'Generate Patch Ticket'}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
