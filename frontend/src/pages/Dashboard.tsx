import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';

export default function Dashboard() {
  const [stats, setStats] = useState({
    total_assets: 0,
    critical_findings: 0,
    high_findings: 0,
    recent_scans: [] as any[]
  });
  const [loading, setLoading] = useState(true);
  const [filterTarget, setFilterTarget] = useState('');
  const [filterType, setFilterType] = useState('');
  const [filterStatus, setFilterStatus] = useState('');

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const token = localStorage.getItem('token');
        const res = await fetch('http://localhost:8000/dashboard/stats', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (res.ok) {
          const data = await res.json();
          setStats(data);
        }
      } catch (err) {
        console.error("Failed to fetch dashboard stats", err);
      } finally {
        setLoading(false);
      }
    };
    fetchStats();
  }, []);

  const filteredScans = stats.recent_scans.filter((scan: any) => {
    return (
      (filterTarget === '' || scan.target === filterTarget) &&
      (filterType === '' || scan.type === filterType) &&
      (filterStatus === '' || scan.status === filterStatus)
    );
  });

  const uniqueTargets = Array.from(new Set(stats.recent_scans.map((s: any) => s.target))).filter(Boolean).sort();
  const uniqueTypes = Array.from(new Set(stats.recent_scans.map((s: any) => s.type))).filter(Boolean).sort();
  const uniqueStatuses = Array.from(new Set(stats.recent_scans.map((s: any) => s.status))).filter(Boolean).sort();

  return (
    <div className="flex-1 p-8">
      <h1 className="text-3xl font-semibold mb-6">Security Dashboard</h1>
        
        {loading ? (
          <p>Loading dashboard...</p>
        ) : (
          <>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
              <Link to="/devices" className="bg-white rounded-lg shadow p-6 border-t-4 border-blue-500 hover:shadow-md transition-shadow">
                <h3 className="text-gray-500 text-sm font-medium">Total Assets</h3>
                <p className="text-3xl font-bold mt-2">{stats.total_assets}</p>
              </Link>
              <Link to="/findings" className="bg-white rounded-lg shadow p-6 border-t-4 border-red-500 hover:shadow-md transition-shadow">
                <h3 className="text-gray-500 text-sm font-medium">Critical Findings</h3>
                <p className="text-3xl font-bold mt-2 text-red-600">{stats.critical_findings}</p>
              </Link>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-xl font-semibold mb-4">Recent Scans</h2>
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b">
                    <th className="py-2 align-top">
                      <div className="mb-1">Target</div>
                      <select 
                        className="border rounded px-2 py-1 text-xs w-full font-normal"
                        value={filterTarget}
                        onChange={(e) => setFilterTarget(e.target.value)}
                      >
                        <option value="">All</option>
                        {uniqueTargets.map((t: any, idx) => (
                          <option key={idx} value={t}>{t}</option>
                        ))}
                      </select>
                    </th>
                    <th className="py-2 align-top">
                      <div className="mb-1">Type</div>
                      <select 
                        className="border rounded px-2 py-1 text-xs w-full font-normal"
                        value={filterType}
                        onChange={(e) => setFilterType(e.target.value)}
                      >
                        <option value="">All</option>
                        {uniqueTypes.map((t: any, idx) => (
                          <option key={idx} value={t}>{t}</option>
                        ))}
                      </select>
                    </th>
                    <th className="py-2 align-top">
                      <div className="mb-1">Status</div>
                      <select 
                        className="border rounded px-2 py-1 text-xs w-full font-normal"
                        value={filterStatus}
                        onChange={(e) => setFilterStatus(e.target.value)}
                      >
                        <option value="">All</option>
                        {uniqueStatuses.map((s: any, idx) => (
                          <option key={idx} value={s}>{s}</option>
                        ))}
                      </select>
                    </th>
                    <th className="py-2 align-top">
                      <div className="mb-1">Completed</div>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {filteredScans.length === 0 ? (
                    <tr><td colSpan={4} className="py-4 text-gray-500 text-center">No scans found matching filters.</td></tr>
                  ) : (
                    filteredScans.map((scan) => (
                      <tr 
                        key={scan.id} 
                        className="border-b hover:bg-gray-50 cursor-pointer" 
                        onClick={() => window.location.href='/scans'}
                      >
                        <td className="py-3 font-mono text-sm">{scan.target}</td>
                        <td className="py-3">{scan.type}</td>
                        <td className="py-3">
                          <span className={`px-2 py-1 rounded-full text-xs ${scan.status === 'COMPLETED' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'}`}>
                            {scan.status}
                          </span>
                        </td>
                        <td className="py-3 text-sm text-gray-600">
                          {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : 'N/A'}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
  );
}
