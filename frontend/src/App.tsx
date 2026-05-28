import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import DeviceInventory from './pages/DeviceInventory';
import ScanExecution from './pages/ScanExecution';
import FindingsTable from './pages/FindingsTable';
import VulnerabilityDetail from './pages/VulnerabilityDetail';
import Remediation from './pages/Remediation';
import Reporting from './pages/Reporting';
import AdminSettings from './pages/AdminSettings';
import BackupManager from './pages/BackupManager';

function App() {
  return (
    <Routes>
      <Route path="/" element={<Login />} />
      
      {/* Protected Routes inside Layout */}
      <Route element={<Layout />}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/devices" element={<DeviceInventory />} />
        <Route path="/scans" element={<ScanExecution />} />
        <Route path="/findings" element={<FindingsTable />} />
        <Route path="/findings/:id" element={<VulnerabilityDetail />} />
        <Route path="/remediation" element={<Remediation />} />
        <Route path="/reports" element={<Reporting />} />
        <Route path="/backup" element={<BackupManager />} />
        <Route path="/admin" element={<AdminSettings />} />
      </Route>
    </Routes>
  )
}

export default App;
