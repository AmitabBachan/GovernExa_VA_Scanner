import { useState, useEffect } from 'react';

interface User {
  id: number;
  email: string;
  role: string;
  is_active: boolean;
}

export default function AdminSettings() {
  const [users, setUsers] = useState<User[]>([]);
  const [cloudStatus, setCloudStatus] = useState<Record<string, boolean>>({});
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState<number | null>(null);
  
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [roleName, setRoleName] = useState('viewer');

  const [webhookUrl, setWebhookUrl] = useState('');
  const [webhookAuth, setWebhookAuth] = useState('');
  
  const [aiReportMode, setAiReportMode] = useState('false');
  const [aiProvider, setAiProvider] = useState('openai');
  const [aiApiKey, setAiApiKey] = useState('');
  const [aiModel, setAiModel] = useState('');

  // Credentials State
  const [credentials, setCredentials] = useState<any[]>([]);
  const [showCredModal, setShowCredModal] = useState(false);
  const [credName, setCredName] = useState('');
  const [credType, setCredType] = useState('ssh');
  const [credUser, setCredUser] = useState('');
  const [credPass, setCredPass] = useState('');
  const [credKey, setCredKey] = useState('');

  // License State
  const [licenseInfo, setLicenseInfo] = useState<{
    company: string;
    valid_from: string;
    valid_to: string;
    days_remaining: number;
    status: string;
  }>({
    company: 'Loading...',
    valid_from: '-',
    valid_to: '-',
    days_remaining: 0,
    status: 'Unlicensed'
  });
  const [machineFingerprint, setMachineFingerprint] = useState<string>('Loading...');

  const fetchFingerprint = async () => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch('http://localhost:8000/api/licensing/fingerprint', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setMachineFingerprint(data.machine_fingerprint);
      }
    } catch (e) {
      setMachineFingerprint('Failed to load fingerprint');
    }
  };

  const fetchUsers = async () => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch('http://localhost:8000/users/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        setUsers(await res.json());
      }
    } catch (e) {
      console.error(e);
    }
  };

  const fetchSettings = async () => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch('http://localhost:8000/settings/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setWebhookUrl(data.webhook_url || '');
        setWebhookAuth(data.webhook_auth_token || '');
        setAiReportMode(data.ai_report_mode || 'false');
        setAiProvider(data.ai_provider || 'openai');
        setAiApiKey(data.ai_api_key || '');
        setAiModel(data.ai_model || '');
      }
    } catch (e) {
      console.error(e);
    }
  };

  const fetchCredentials = async () => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch('http://localhost:8000/credentials/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        setCredentials(await res.json());
      }
    } catch (e) {
      console.error(e);
    }
  };

  const fetchLicense = async () => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch('http://localhost:8000/api/licensing/status', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        // data contains: status, license_key, customer, tier, issued_at, expires_at, features
        const validFrom = data.issued_at ? new Date(data.issued_at) : null;
        const validTo = data.expires_at ? new Date(data.expires_at) : null;
        let daysRemaining = -1;
        if (validTo) {
          const diffTime = Math.abs(validTo.getTime() - new Date().getTime());
          daysRemaining = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
        }

        setLicenseInfo({
          company: data.customer || 'Unknown',
          valid_from: validFrom ? validFrom.toLocaleDateString() : 'Date of Activation',
          valid_to: validTo ? validTo.toLocaleDateString() : 'Never',
          days_remaining: daysRemaining,
          status: data.status === 'active' ? 'Active' : data.status
        });
      } else {
        setLicenseInfo({
          company: 'No Active License',
          valid_from: '-',
          valid_to: '-',
          days_remaining: 0,
          status: 'Unlicensed'
        });
      }
    } catch (e) {
      setLicenseInfo({
        company: 'Error loading license',
        valid_from: '-',
        valid_to: '-',
        days_remaining: 0,
        status: 'Error'
      });
    }
  };

  useEffect(() => {
    fetchUsers();
    fetchSettings();
    fetchCredentials();
    fetchLicense();
    fetchFingerprint();
  }, []);

  const handleActivateOnline = async () => {
    const key = prompt('Enter License Key (e.g. XXXX-XXXX-XXXX-XXXX):');
    if (!key) return;
    
    try {
      const token = localStorage.getItem('token');
      const res = await fetch('http://localhost:8000/api/licensing/activate/online', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}` 
        },
        body: JSON.stringify({ license_key: key, device_id: 'local-browser-device' })
      });
      if (res.ok) {
        alert('Online activation successful (simulated)!');
        fetchLicense();
      } else {
        const err = await res.json();
        alert('Activation failed: ' + err.detail);
      }
    } catch (e) {
      alert('Network error');
    }
  };

  const handleUploadLicense = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = async (e: any) => {
      const file = e.target.files[0];
      if (!file) return;
      
      const reader = new FileReader();
      reader.onload = async (event: any) => {
        let content;
        try {
          content = JSON.parse(event.target.result);
        } catch (e: any) {
          alert('Error parsing JSON file: ' + e.message);
          return;
        }

        if (!content.license_token) {
          alert('Invalid license file format.');
          return;
        }
        
        try {
          const token = localStorage.getItem('token');
          const res = await fetch('http://localhost:8000/api/licensing/activate/offline', {
            method: 'POST',
            headers: { 
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${token}` 
            },
            body: JSON.stringify({ license_token: content.license_token, device_id: 'local-browser-device' })
          });
          
          if (res.ok) {
            alert('License activated successfully.');
            fetchLicense();
          } else {
            const err = await res.json();
            // Try to map error message based on backend strings
            if (err.detail && err.detail.includes("consumed")) {
              alert('This license has already been consumed and cannot be reused.');
            } else if (err.detail && err.detail.includes("another GovernExa installation")) {
              alert('This license belongs to another GovernExa installation.');
            } else if (err.detail && err.detail.includes("tampering")) {
              alert('License validation failed. Activation rejected.');
            } else {
              alert('Activation failed: ' + err.detail);
            }
          }
        } catch (e: any) {
          alert('Network/API Error: ' + e.message);
        }
      };
      reader.readAsText(file);
    };
    input.click();
  };

  const handleFlush = async () => {
    if (!confirm("Are you sure you want to completely flush the licensing database? This is a temporary dev feature.")) return;
    try {
      const token = localStorage.getItem('token');
      const res = await fetch('http://localhost:8000/api/licensing/flush', {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        alert("Database flushed successfully.");
        fetchLicense();
      } else {
        alert("Failed to flush database.");
      }
    } catch (e: any) {
      alert("Error flushing: " + e.message);
    }
  };

  const handleAddUser = async () => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch('http://localhost:8000/users/', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}` 
        },
        body: JSON.stringify({ email, password, role_name: roleName })
      });
      if (res.ok) {
        setShowAddModal(false);
        setEmail('');
        setPassword('');
        fetchUsers();
      } else {
        alert('Failed to add user');
      }
    } catch (e) {
      alert('Network error');
    }
  };

  const handleEditUser = async (id: number) => {
    try {
      const token = localStorage.getItem('token');
      const payload: any = { role_name: roleName };
      if (password) payload.password = password;
      
      const res = await fetch(`http://localhost:8000/users/${id}`, {
        method: 'PUT',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}` 
        },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        setShowEditModal(null);
        setPassword('');
        fetchUsers();
      } else {
        alert('Failed to edit user');
      }
    } catch (e) {
      alert('Network error');
    }
  };

  const handleConfigureCloud = (provider: string) => {
    // Mocking cloud configuration saving
    const mockKey = prompt(`Enter ${provider} Service Credentials / Key:`);
    if (mockKey) {
      setCloudStatus({ ...cloudStatus, [provider]: true });
      alert(`${provider} configured successfully!`);
    }
  };

  const handleSaveWebhooks = async () => {
    try {
      const token = localStorage.getItem('token');
      const payload = {
        settings: {
          webhook_url: webhookUrl,
          webhook_auth_token: webhookAuth,
          ai_report_mode: aiReportMode,
          ai_provider: aiProvider,
          ai_api_key: aiApiKey,
          ai_model: aiModel
        }
      };
      const res = await fetch('http://localhost:8000/settings/', {
        method: 'PUT',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}` 
        },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        alert('Settings saved successfully!');
      } else {
        alert('Failed to save settings');
      }
    } catch (e) {
      alert('Network error while saving settings');
    }
  };

  const handleAddCredential = async () => {
    try {
      const token = localStorage.getItem('token');
      const payload = {
        name: credName,
        auth_type: credType,
        username: credUser,
        password: credPass,
        private_key: credKey
      };
      const res = await fetch('http://localhost:8000/credentials/', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}` 
        },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        setShowCredModal(false);
        setCredName(''); setCredUser(''); setCredPass(''); setCredKey('');
        fetchCredentials();
      } else {
        alert('Failed to add credential');
      }
    } catch (e) {
      alert('Network error');
    }
  };

  const handleDeleteCredential = async (id: number) => {
    if (!confirm('Are you sure you want to delete this credential?')) return;
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`http://localhost:8000/credentials/${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        fetchCredentials();
      }
    } catch (e) {
      console.error(e);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'Active':
        return <span className="px-3 py-1 bg-green-100 text-green-800 rounded-full text-sm font-semibold">Active</span>;
      case 'Expiring Soon':
        return <span className="px-3 py-1 bg-yellow-100 text-yellow-800 rounded-full text-sm font-semibold">Expiring Soon</span>;
      case 'Expired':
        return <span className="px-3 py-1 bg-red-100 text-red-800 rounded-full text-sm font-semibold">Expired</span>;
      default:
        return <span className="px-3 py-1 bg-gray-100 text-gray-800 rounded-full text-sm font-semibold">{status}</span>;
    }
  };

  return (
    <div className="p-8 max-w-4xl relative">
      <h1 className="text-2xl font-bold mb-6">Admin Settings</h1>
      
      <div className="bg-white rounded-lg shadow p-6 mb-8">
        <h2 className="text-xl font-semibold mb-4 border-b pb-2">Licensing & Activation</h2>
        
        <div className="flex justify-between items-start mb-6">
          <div className="space-y-2">
            <p><span className="font-medium text-gray-700">Company:</span> {licenseInfo.company}</p>
            <p><span className="font-medium text-gray-700">Valid From:</span> {licenseInfo.valid_from}</p>
            <p><span className="font-medium text-gray-700">Valid To:</span> {licenseInfo.valid_to}</p>
            <p><span className="font-medium text-gray-700">Days Remaining:</span> {licenseInfo.days_remaining}</p>
            <p><span className="font-medium text-gray-700">Machine Fingerprint:</span> <span className="font-mono bg-gray-100 px-1 py-0.5 rounded text-xs">{machineFingerprint}</span></p>
            <p className="text-xs text-gray-500 mt-2">Provide this Machine Fingerprint to the vendor to generate a license file.</p>
          </div>
          <div>
            {getStatusBadge(licenseInfo.status)}
          </div>
        </div>

        <div className="flex gap-3 border-t pt-4">
          <button onClick={handleActivateOnline} className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 text-sm font-medium">
            Activate Online
          </button>
          <button onClick={handleUploadLicense} className="px-4 py-2 bg-gray-100 text-gray-800 border border-gray-300 rounded hover:bg-gray-200 text-sm font-medium">
            Upload License File
          </button>
          <button onClick={handleFlush} className="px-4 py-2 bg-red-100 text-red-800 border border-red-300 rounded hover:bg-red-200 text-sm font-medium ml-auto">
            Flush DB (Test)
          </button>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow p-6 mb-8">
        <h2 className="text-xl font-semibold mb-4 border-b pb-2">Cloud Integrations</h2>
        <div className="space-y-4">
          {/* AWS Integration */}
          <div className="flex justify-between items-center">
            <div>
              <p className="font-medium">AWS Connect</p>
              <p className="text-sm text-gray-500">Sync EC2 instances dynamically.</p>
            </div>
            <div className="flex items-center gap-3">
              {cloudStatus['AWS'] && <span className="text-green-600 font-medium">Configured</span>}
              <button onClick={() => handleConfigureCloud('AWS')} className="px-4 py-2 bg-blue-50 text-blue-600 rounded hover:bg-blue-100">
                {cloudStatus['AWS'] ? 'Edit' : 'Configure'}
              </button>
            </div>
          </div>
          
          {/* GCP Integration */}
          <div className="flex justify-between items-center">
            <div>
              <p className="font-medium">GCP Compute Engine</p>
              <p className="text-sm text-gray-500">Sync VM instances dynamically.</p>
            </div>
            <div className="flex items-center gap-3">
              {cloudStatus['GCP'] && <span className="text-green-600 font-medium">Configured</span>}
              <button onClick={() => handleConfigureCloud('GCP')} className="px-4 py-2 bg-blue-50 text-blue-600 rounded hover:bg-blue-100">
                {cloudStatus['GCP'] ? 'Edit' : 'Configure'}
              </button>
            </div>
          </div>

          {/* Azure Integration */}
          <div className="flex justify-between items-center">
            <div>
              <p className="font-medium">Microsoft Azure</p>
              <p className="text-sm text-gray-500">Sync Azure Virtual Machines dynamically.</p>
            </div>
            <div className="flex items-center gap-3">
              {cloudStatus['Azure'] && <span className="text-green-600 font-medium">Configured</span>}
              <button onClick={() => handleConfigureCloud('Azure')} className="px-4 py-2 bg-blue-50 text-blue-600 rounded hover:bg-blue-100">
                {cloudStatus['Azure'] ? 'Edit' : 'Configure'}
              </button>
            </div>
          </div>

          {/* Private Cloud / Custom Integration */}
          <div className="flex justify-between items-center">
            <div>
              <p className="font-medium">Private Cloud / On-Premise</p>
              <p className="text-sm text-gray-500">Connect via custom API or vSphere.</p>
            </div>
            <div className="flex items-center gap-3">
              {cloudStatus['Private'] && <span className="text-green-600 font-medium">Configured</span>}
              <button onClick={() => handleConfigureCloud('Private')} className="px-4 py-2 bg-blue-50 text-blue-600 rounded hover:bg-blue-100">
                {cloudStatus['Private'] ? 'Edit' : 'Configure'}
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow p-6 mb-8">
        <h2 className="text-xl font-semibold mb-4 border-b pb-2">API & Webhooks</h2>
        <div className="space-y-4">
          <p className="text-sm text-gray-600 mb-4">
            Configure external integrations, such as automatically pushing JSON tickets for Remediations to third-party tools like Jira, ServiceNow, or custom listeners.
          </p>
          <div>
            <label className="block text-sm font-medium mb-1 text-gray-700">Ticketing Webhook URL</label>
            <input 
              type="text" 
              placeholder="https://your-ticketing-tool.com/api/webhook" 
              value={webhookUrl} 
              onChange={e => setWebhookUrl(e.target.value)} 
              className="w-full border rounded p-2 focus:ring-2 focus:ring-blue-500 outline-none" 
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1 text-gray-700">Authorization Token / Header (Optional)</label>
            <input 
              type="text" 
              placeholder="Bearer your_api_token_here" 
              value={webhookAuth} 
              onChange={e => setWebhookAuth(e.target.value)} 
              className="w-full border rounded p-2 focus:ring-2 focus:ring-blue-500 outline-none" 
            />
          </div>
          <div className="flex justify-end mt-4">
            <button onClick={handleSaveWebhooks} className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">
              Save Webhook Config
            </button>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow p-6 mb-8">
        <h2 className="text-xl font-semibold mb-4 border-b pb-2">AI Report Enrichment Engine</h2>
        <div className="space-y-4">
          <p className="text-sm text-gray-600 mb-4">
            Configure the AI provider to automatically generate plain-language explanations and remediation steps during report generation. If disabled or no key is provided, the report will use standard database findings.
          </p>
          <div>
            <label className="block text-sm font-medium mb-1 text-gray-700">Enable AI Enrichment</label>
            <select 
              value={aiReportMode} 
              onChange={e => setAiReportMode(e.target.value)} 
              className="w-full border rounded p-2 focus:ring-2 focus:ring-blue-500 outline-none"
            >
              <option value="false">Disabled</option>
              <option value="true">Enabled</option>
            </select>
          </div>
          {aiReportMode === 'true' && (
            <>
              <div>
                <label className="block text-sm font-medium mb-1 text-gray-700">AI Provider</label>
                <select 
                  value={aiProvider} 
                  onChange={e => setAiProvider(e.target.value)} 
                  className="w-full border rounded p-2 focus:ring-2 focus:ring-blue-500 outline-none"
                >
                  <option value="openai">OpenAI (ChatGPT)</option>
                  <option value="google">Google (Gemini)</option>
                  <option value="local">Local Endpoint (LM Studio, vLLM, Ollama)</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1 text-gray-700">Model Name</label>
                <input 
                  type="text" 
                  placeholder={aiProvider === 'openai' ? 'gpt-4-turbo' : aiProvider === 'google' ? 'gemini-1.5-pro-latest' : 'local-model'} 
                  value={aiModel} 
                  onChange={e => setAiModel(e.target.value)} 
                  className="w-full border rounded p-2 focus:ring-2 focus:ring-blue-500 outline-none" 
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1 text-gray-700">{aiProvider === 'local' ? 'Endpoint URL (with scheme & /v1/chat/completions)' : 'API Key'}</label>
                <input 
                  type="password" 
                  placeholder={aiProvider === 'local' ? 'http://localhost:1234/v1/chat/completions' : 'Enter API Key'} 
                  value={aiApiKey} 
                  onChange={e => setAiApiKey(e.target.value)} 
                  className="w-full border rounded p-2 focus:ring-2 focus:ring-blue-500 outline-none" 
                />
              </div>
            </>
          )}
          <div className="flex justify-end mt-4">
            <button onClick={handleSaveWebhooks} className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">
              Save AI Settings
            </button>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow p-6 mb-8">
        <div className="flex justify-between items-center border-b pb-2 mb-4">
          <h2 className="text-xl font-semibold">Scan Credentials</h2>
          <button onClick={() => setShowCredModal(true)} className="px-3 py-1 bg-green-600 text-white rounded hover:bg-green-700 text-sm">
            + Add Credential
          </button>
        </div>
        <p className="text-sm text-gray-600 mb-4">
          Manage credentials for Authenticated Deep Scans (SSH, WinRM).
        </p>
        <div className="space-y-4">
          {credentials.length === 0 ? (
            <p className="text-gray-500 italic text-sm">No credentials saved.</p>
          ) : credentials.map(c => (
            <div key={c.id} className="flex justify-between items-center bg-gray-50 p-4 rounded border border-gray-100">
              <div>
                <p className="font-medium text-gray-800">{c.name} <span className="text-xs uppercase bg-gray-200 px-2 py-0.5 rounded text-gray-700 ml-2">{c.auth_type}</span></p>
                <p className="text-sm text-gray-500">Username: {c.username}</p>
              </div>
              <div className="flex gap-2">
                <button onClick={() => handleDeleteCredential(c.id)} className="px-3 py-1 text-red-600 hover:text-red-900 border border-red-200 rounded hover:bg-red-50 text-sm transition-colors">
                  Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold mb-4 border-b pb-2">User Management (RBAC)</h2>
        <div className="space-y-4">
          {users.map(u => (
            <div key={u.id} className="flex justify-between items-center bg-gray-50 p-4 rounded border border-gray-100">
              <div>
                <p className="font-medium">{u.email}</p>
                <p className="text-sm text-gray-500">Role: <span className="capitalize">{u.role}</span></p>
              </div>
              <button 
                onClick={() => {
                  setRoleName(u.role);
                  setShowEditModal(u.id);
                }} 
                className="text-blue-600 hover:underline"
              >
                Edit
              </button>
            </div>
          ))}
          <button onClick={() => { setEmail(''); setPassword(''); setShowAddModal(true); }} className="mt-4 px-4 py-2 bg-gray-800 text-white rounded hover:bg-gray-900">Add User</button>
        </div>
      </div>

      {/* Add User Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white p-6 rounded-lg shadow-lg w-96">
            <h3 className="text-lg font-bold mb-4">Add New User</h3>
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium mb-1">Email</label>
                <input type="email" value={email} onChange={e => setEmail(e.target.value)} className="w-full border rounded p-2" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Password</label>
                <input type="password" value={password} onChange={e => setPassword(e.target.value)} className="w-full border rounded p-2" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Role</label>
                <select value={roleName} onChange={e => setRoleName(e.target.value)} className="w-full border rounded p-2">
                  <option value="viewer">Viewer</option>
                  <option value="scanner">Scanner</option>
                  <option value="admin">Administrator</option>
                </select>
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button onClick={() => setShowAddModal(false)} className="px-4 py-2 bg-gray-200 rounded">Cancel</button>
              <button onClick={handleAddUser} className="px-4 py-2 bg-blue-600 text-white rounded">Save</button>
            </div>
          </div>
        </div>
      )}

      {/* Edit User Modal */}
      {showEditModal !== null && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white p-6 rounded-lg shadow-lg w-96">
            <h3 className="text-lg font-bold mb-4">Edit User</h3>
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium mb-1">New Password (Optional)</label>
                <input type="password" placeholder="Leave blank to keep current" value={password} onChange={e => setPassword(e.target.value)} className="w-full border rounded p-2" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Role</label>
                <select value={roleName} onChange={e => setRoleName(e.target.value)} className="w-full border rounded p-2">
                  <option value="viewer">Viewer</option>
                  <option value="scanner">Scanner</option>
                  <option value="admin">Administrator</option>
                </select>
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button onClick={() => setShowEditModal(null)} className="px-4 py-2 bg-gray-200 rounded">Cancel</button>
              <button onClick={() => handleEditUser(showEditModal)} className="px-4 py-2 bg-blue-600 text-white rounded">Save Changes</button>
            </div>
          </div>
        </div>
      )}

      {/* Add Credential Modal */}
      {showCredModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex justify-center items-center z-50">
          <div className="bg-white p-6 rounded-lg w-[500px]">
            <h3 className="text-xl font-bold mb-4">Add Scan Credential</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Credential Name</label>
                <input type="text" className="w-full border rounded p-2 outline-none focus:border-blue-500" value={credName} onChange={e => setCredName(e.target.value)} placeholder="e.g. Production Linux SSH" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Type</label>
                <select className="w-full border rounded p-2 outline-none" value={credType} onChange={e => setCredType(e.target.value)}>
                  <option value="ssh">SSH (Linux)</option>
                  <option value="winrm">WinRM (Windows)</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Username</label>
                <input type="text" className="w-full border rounded p-2 outline-none focus:border-blue-500" value={credUser} onChange={e => setCredUser(e.target.value)} />
              </div>
              
              {credType === 'ssh' ? (
                <>
                  <div>
                    <label className="block text-sm font-medium mb-1">Password (Optional if using Key)</label>
                    <input type="password" className="w-full border rounded p-2 outline-none focus:border-blue-500" value={credPass} onChange={e => setCredPass(e.target.value)} />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1">Private Key (Optional)</label>
                    <textarea className="w-full border rounded p-2 outline-none focus:border-blue-500 font-mono text-xs" rows={4} value={credKey} onChange={e => setCredKey(e.target.value)} placeholder="-----BEGIN RSA PRIVATE KEY-----..."></textarea>
                  </div>
                </>
              ) : (
                <div>
                  <label className="block text-sm font-medium mb-1">Password</label>
                  <input type="password" className="w-full border rounded p-2 outline-none focus:border-blue-500" value={credPass} onChange={e => setCredPass(e.target.value)} />
                </div>
              )}
            </div>
            <div className="mt-6 flex justify-end gap-3">
              <button onClick={() => setShowCredModal(false)} className="px-4 py-2 text-gray-600 hover:text-gray-900">Cancel</button>
              <button onClick={handleAddCredential} className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">Save</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
