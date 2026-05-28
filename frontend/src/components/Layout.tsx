import { Link, Outlet, useLocation } from 'react-router-dom';
import { Logo } from './Logo';

export default function Layout() {
  const location = useLocation();

  const navItem = (path: string, label: string) => {
    const isActive = location.pathname.startsWith(path);
    return (
      <Link 
        to={path} 
        className={`block px-4 py-2 rounded ${isActive ? 'bg-gray-800 text-blue-400 font-medium' : 'text-white hover:bg-gray-800'}`}
      >
        {label}
      </Link>
    );
  };

  return (
    <div className="min-h-screen bg-gray-50 flex">
      {/* Sidebar */}
      <div className="w-64 bg-gray-900 text-white min-h-screen p-4 flex flex-col fixed h-full">
        <div className="mb-10 mt-4 px-2">
            <Logo variant="light" stacked={false} className="h-10" />
        </div>
        <nav className="space-y-2 flex-1">
          {navItem('/dashboard', 'Dashboard')}
          {navItem('/devices', 'Inventory')}
          {navItem('/scans', 'Scans')}
          {navItem('/findings', 'Findings')}
          {navItem('/remediation', 'Remediation')}
          {navItem('/reports', 'Reports')}
          {navItem('/backup', 'Data Backup')}
          {navItem('/admin', 'Settings')}
        </nav>
        <div className="mt-auto">
          <button 
            onClick={() => {
              localStorage.removeItem('token');
              window.location.href = '/';
            }}
            className="w-full text-left px-4 py-2 rounded text-gray-400 hover:text-white hover:bg-gray-800"
          >
            Logout
          </button>
        </div>
      </div>

      {/* Main Content Area (Offset by sidebar width) */}
      <div className="flex-1 ml-64 overflow-y-auto">
        <Outlet />
      </div>
    </div>
  );
}
