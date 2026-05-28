import re

with open('frontend/src/pages/ScanExecution.tsx', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add state for validation
state_target = "  const [riskScoringJobId, setRiskScoringJobId] = useState<string | null>(null);"
state_replacement = """  const [riskScoringJobId, setRiskScoringJobId] = useState<string | null>(null);
  const [validationData, setValidationData] = useState<any[]>([]);
  const [validationJobId, setValidationJobId] = useState<string | null>(null);
  const [validationFilter, setValidationFilter] = useState('');"""
content = content.replace(state_target, state_replacement)

# 2. Add AVAILABLE_SCANS option
scans_target = """    { id: 'risk_scoring', name: 'Risk Scoring' }
  ];"""
scans_replacement = """    { id: 'validation', name: 'Validation / Verification' },
    { id: 'risk_scoring', name: 'Risk Scoring' }
  ];"""
content = content.replace(scans_target, scans_replacement)

# 3. Add fetchValidationResults method
fetch_target = """  const fetchRiskScoringResults = async (id: string) => {"""
fetch_replacement = """  const fetchValidationResults = async (id: string) => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`http://localhost:8000/scan/${id}/validation`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setValidationData(data);
        setValidationJobId(id);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const fetchRiskScoringResults = async (id: string) => {"""
content = content.replace(fetch_target, fetch_replacement)

# 4. Add Full Scan UI progress phase
full_scan_target = """                <div className={`text-sm ${logs.some(l => l.includes('[RiskScoring] Starting Contextual Risk Scoring')) ? 'text-indigo-600 font-semibold' : 'text-gray-400'}`}>7. Risk Scoring</div>
              </div>
            </div>
          </div>"""
full_scan_replacement = """                <div className={`text-sm ${logs.some(l => l.includes('[Validation] Starting Validation & Verification')) ? 'text-indigo-600 font-semibold' : 'text-gray-400'}`}>7. Validation</div>
                <div className={`text-sm ${logs.some(l => l.includes('[RiskScoring] Starting Contextual Risk Scoring')) ? 'text-indigo-600 font-semibold' : 'text-gray-400'}`}>8. Risk Scoring</div>
              </div>
            </div>
          </div>"""
content = content.replace(full_scan_target, full_scan_replacement)

# 5. Add UI table to view results
ui_table_target = """      {/* Risk Scoring Modal/Table */}
      {riskScoringJobId && (
        <div className="mt-8 bg-white rounded-lg shadow overflow-hidden">
          <div className="bg-indigo-600 px-6 py-4 flex justify-between items-center text-white">"""
ui_table_replacement = """      {/* Validation Modal/Table */}
      {validationJobId && (
        <div className="mt-8 bg-white rounded-lg shadow overflow-hidden">
          <div className="bg-indigo-600 px-6 py-4 flex justify-between items-center text-white">
            <h3 className="text-xl font-bold">Validation & Verification Results</h3>
            <button onClick={() => setValidationJobId(null)} className="text-white hover:text-gray-200">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
            </button>
          </div>
          <div className="p-6">
            <div className="mb-4">
              <input 
                type="text" 
                placeholder="Filter by Vulnerability ID..." 
                className="border p-2 rounded w-full md:w-1/3"
                value={validationFilter}
                onChange={(e) => setValidationFilter(e.target.value)}
              />
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-full text-sm">
                <thead>
                  <tr className="bg-gray-100 border-b">
                    <th className="px-4 py-2 text-left">IP Address</th>
                    <th className="px-4 py-2 text-left">Vulnerability ID</th>
                    <th className="px-4 py-2 text-left">Status</th>
                    <th className="px-4 py-2 text-left">Method</th>
                    <th className="px-4 py-2 text-left">Proof of Concept</th>
                  </tr>
                </thead>
                <tbody>
                  {validationData.length === 0 ? (
                    <tr><td colSpan={5} className="px-4 py-4 text-center text-gray-500">No validation records found for this scan.</td></tr>
                  ) : (
                    validationData
                      .filter(v => validationFilter === '' || (v.vulnerability_id && v.vulnerability_id.toLowerCase().includes(validationFilter.toLowerCase())))
                      .map((v, idx) => (
                      <tr key={idx} className="border-b hover:bg-gray-50">
                        <td className="px-4 py-2 whitespace-nowrap">{v.ip_address}</td>
                        <td className="px-4 py-2 font-mono">{v.vulnerability_id}</td>
                        <td className="px-4 py-2">
                            {v.is_false_positive ? (
                                <span className="bg-red-100 text-red-800 px-2 py-1 rounded text-xs font-semibold">False Positive</span>
                            ) : v.is_confirmed ? (
                                <span className="bg-green-100 text-green-800 px-2 py-1 rounded text-xs font-semibold">Confirmed</span>
                            ) : (
                                <span className="bg-gray-100 text-gray-800 px-2 py-1 rounded text-xs font-semibold">Pending/Unknown</span>
                            )}
                        </td>
                        <td className="px-4 py-2">{v.verification_method || 'N/A'}</td>
                        <td className="px-4 py-2 whitespace-pre-wrap max-w-xs">{v.proof_of_concept}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Risk Scoring Modal/Table */}
      {riskScoringJobId && (
        <div className="mt-8 bg-white rounded-lg shadow overflow-hidden">
          <div className="bg-indigo-600 px-6 py-4 flex justify-between items-center text-white">"""
content = content.replace(ui_table_target, ui_table_replacement)


# 6. Add action button to view Validation Results in History table
# Looking around line 1500 or so where actions are defined... I should just regex for the last button before Risk Scoring.
actions_target = """                            {(job.scan_type === 'auth_scan' || job.scan_type === 'full_scan') && (
                              <>
                                <span className="text-gray-300">|</span>
                                <button
                                  onClick={() => fetchAuthScanResults(job.scan_job_id)}
                                  className="text-pink-600 hover:text-pink-900 font-medium flex items-center"
                                >
                                  🔑 Auth Scan
                                </button>
                              </>
                            )}"""
actions_replacement = """                            {(job.scan_type === 'auth_scan' || job.scan_type === 'full_scan') && (
                              <>
                                <span className="text-gray-300">|</span>
                                <button
                                  onClick={() => fetchAuthScanResults(job.scan_job_id)}
                                  className="text-pink-600 hover:text-pink-900 font-medium flex items-center"
                                >
                                  🔑 Auth Scan
                                </button>
                              </>
                            )}
                            {(job.scan_type === 'validation' || job.scan_type === 'full_scan') && (
                              <>
                                <span className="text-gray-300">|</span>
                                <button
                                  onClick={() => fetchValidationResults(job.scan_job_id)}
                                  className="text-teal-600 hover:text-teal-900 font-medium flex items-center"
                                >
                                  ✅ Validation
                                </button>
                              </>
                            )}"""
content = content.replace(actions_target, actions_replacement)


with open('frontend/src/pages/ScanExecution.tsx', 'w', encoding='utf-8') as f:
    f.write(content)
print("ScanExecution.tsx updated with Validation UI")
