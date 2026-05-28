import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';

export default function DeviceInventory() {
  const [devices, setDevices] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterIp, setFilterIp] = useState('');
  const [filterHostname, setFilterHostname] = useState('');
  const [filterOs, setFilterOs] = useState('');

  useEffect(() => {
    const fetchDevices = async () => {
      try {
        const token = localStorage.getItem('token');
        const res = await fetch('http://localhost:8000/devices/', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (res.ok) {
          const data = await res.json();
          setDevices(data.data || []);
        }
      } catch (err) {
        console.error("Failed to fetch devices", err);
      } finally {
        setLoading(false);
      }
    };
    fetchDevices();
  }, []);

  const filteredDevices = devices.filter(d => {
    return (
      (filterIp === '' || d.ip === filterIp) &&
      (filterHostname === '' || (d.hostname && d.hostname === filterHostname)) &&
      (filterOs === '' || (d.os && d.os === filterOs))
    );
  });

  // Extract unique values for dropdowns
  const uniqueIps = Array.from(new Set(devices.map(d => d.ip))).filter(Boolean).sort();
  const uniqueHostnames = Array.from(new Set(devices.map(d => d.hostname || 'Unknown'))).filter(Boolean).sort();
  const uniqueOs = Array.from(new Set(devices.map(d => d.os || 'Unknown'))).filter(Boolean).sort();

  return (
    <div className="p-8">
      <h1 className="text-2xl font-bold mb-6">Device Inventory</h1>
      <div className="bg-white rounded-lg shadow overflow-hidden">
        {loading ? (
          <div className="p-4">Loading devices...</div>
        ) : (
          <table className="w-full text-left border-collapse">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 border-b text-sm font-semibold text-gray-700 align-top">
                  <div className="mb-1">IP Address</div>
                  <select 
                    className="border rounded px-2 py-1 text-xs w-full font-normal"
                    value={filterIp}
                    onChange={(e) => setFilterIp(e.target.value)}
                  >
                    <option value="">All</option>
                    {uniqueIps.map((ip: any, idx) => (
                      <option key={idx} value={ip}>{ip}</option>
                    ))}
                  </select>
                </th>
                <th className="px-6 py-3 border-b text-sm font-semibold text-gray-700 align-top">
                  <div className="mb-1">Hostname</div>
                  <select 
                    className="border rounded px-2 py-1 text-xs w-full font-normal"
                    value={filterHostname}
                    onChange={(e) => setFilterHostname(e.target.value)}
                  >
                    <option value="">All</option>
                    {uniqueHostnames.map((host: any, idx) => (
                      <option key={idx} value={host}>{host}</option>
                    ))}
                  </select>
                </th>
                <th className="px-6 py-3 border-b text-sm font-semibold text-gray-700 align-top">
                  <div className="mb-1">OS</div>
                  <select 
                    className="border rounded px-2 py-1 text-xs w-full font-normal"
                    value={filterOs}
                    onChange={(e) => setFilterOs(e.target.value)}
                  >
                    <option value="">All</option>
                    {uniqueOs.map((os: any, idx) => (
                      <option key={idx} value={os}>{os}</option>
                    ))}
                  </select>
                </th>
                <th className="px-6 py-3 border-b text-sm font-semibold text-gray-700 align-top">
                  <div className="mb-1">MAC</div>
                </th>
                <th className="px-6 py-3 border-b text-sm font-semibold text-gray-700 align-top">
                  <div className="mb-1">Actions</div>
                </th>
              </tr>
            </thead>
            <tbody>
              {filteredDevices.length === 0 ? (
                <tr><td colSpan={5} className="px-6 py-4 text-center">No devices found. Run a scan first.</td></tr>
              ) : (
                filteredDevices.map((d, i) => (
                  <tr key={i} className="border-b hover:bg-gray-50">
                    <td className="px-6 py-4">{d.ip}</td>
                    <td className="px-6 py-4">{d.hostname || 'Unknown'}</td>
                    <td className="px-6 py-4">{d.os || 'Unknown'}</td>
                    <td className="px-6 py-4">{d.mac || 'N/A'}</td>
                    <td className="px-6 py-4"><Link to="/scans" className="text-blue-600 hover:underline">Scan</Link></td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
