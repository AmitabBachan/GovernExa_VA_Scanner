import React, { useState } from 'react';

export default function BackupManager() {
  const [isExporting, setIsExporting] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [statusMsg, setStatusMsg] = useState<{type: 'success' | 'error', text: string} | null>(null);

  const handleExport = async () => {
    setIsExporting(true);
    setStatusMsg(null);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('http://localhost:8000/backup/export', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (response.ok) {
        // Trigger download
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        
        // Extract filename from Content-Disposition if possible, else fallback
        let filename = 'vulnerability_scanner_backup.json';
        const disposition = response.headers.get('Content-Disposition');
        if (disposition && disposition.indexOf('filename=') !== -1) {
            const matches = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/.exec(disposition);
            if (matches != null && matches[1]) {
                filename = matches[1].replace(/['"]/g, '');
            }
        }
        
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        setStatusMsg({ type: 'success', text: 'Backup downloaded successfully!' });
      } else {
        const errorData = await response.json().catch(() => null);
        setStatusMsg({ type: 'error', text: `Export failed: ${errorData?.detail || response.statusText}` });
      }
    } catch (err) {
      console.error(err);
      setStatusMsg({ type: 'error', text: 'Network error during export.' });
    } finally {
      setIsExporting(false);
    }
  };

  const handleImport = async () => {
    if (!selectedFile) {
      setStatusMsg({ type: 'error', text: 'Please select a backup file to restore.' });
      return;
    }
    
    if (!window.confirm("Are you sure you want to restore from this backup? This may overwrite existing matching data.")) {
        return;
    }

    setIsImporting(true);
    setStatusMsg(null);
    
    try {
      const token = localStorage.getItem('token');
      const formData = new FormData();
      formData.append('file', selectedFile);
      
      const response = await fetch('http://localhost:8000/backup/import', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }, // Do NOT set Content-Type, fetch sets it with boundary for FormData
        body: formData
      });
      
      if (response.ok) {
        setStatusMsg({ type: 'success', text: 'Backup restored successfully! All data has been loaded into the database.' });
        setSelectedFile(null);
      } else {
        const errorData = await response.json().catch(() => null);
        setStatusMsg({ type: 'error', text: `Import failed: ${errorData?.detail || response.statusText}` });
      }
    } catch (err) {
      console.error(err);
      setStatusMsg({ type: 'error', text: 'Network error during import.' });
    } finally {
      setIsImporting(false);
    }
  };

  return (
    <div className="p-8 max-w-5xl mx-auto flex flex-col gap-8">
      <div>
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Data Backup & Restore</h1>
        <p className="text-gray-600">Export your scanned data, vulnerabilities, and reports to a secure JSON archive, or restore data from an existing backup.</p>
      </div>

      {statusMsg && (
        <div className={`p-4 rounded-md border ${statusMsg.type === 'success' ? 'bg-green-50 border-green-200 text-green-800' : 'bg-red-50 border-red-200 text-red-800'}`}>
          <p className="font-medium">{statusMsg.text}</p>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        {/* Export Card */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200 flex flex-col h-full">
          <div className="flex items-center gap-3 mb-4">
            <div className="bg-blue-100 p-3 rounded-full text-blue-600">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
            </div>
            <h2 className="text-xl font-bold text-gray-900">Export Data</h2>
          </div>
          
          <p className="text-gray-600 mb-6 flex-1 text-sm">
            Generate a comprehensive JSON backup of all scans, discovered assets, vulnerabilities, risk scores, and generated reports currently stored in the database.
          </p>
          
          <button
            onClick={handleExport}
            disabled={isExporting}
            className="w-full py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-md font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex justify-center items-center gap-2"
          >
            {isExporting ? (
              <>
                <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                Generating Backup...
              </>
            ) : (
              'Download Backup Archive'
            )}
          </button>
        </div>

        {/* Import Card */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200 flex flex-col h-full">
          <div className="flex items-center gap-3 mb-4">
            <div className="bg-green-100 p-3 rounded-full text-green-600">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" /></svg>
            </div>
            <h2 className="text-xl font-bold text-gray-900">Restore Data</h2>
          </div>
          
          <p className="text-gray-600 mb-4 flex-1 text-sm">
            Restore historical scan data by uploading a previously downloaded JSON backup file. This will safely import the records back into your active system.
          </p>
          
          <div className="space-y-4">
            <input
              type="file"
              accept=".json"
              onChange={(e) => setSelectedFile(e.target.files ? e.target.files[0] : null)}
              className="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-green-50 file:text-green-700 hover:file:bg-green-100 border border-gray-200 rounded-md p-1"
            />
            
            <button
              onClick={handleImport}
              disabled={isImporting || !selectedFile}
              className="w-full py-3 bg-green-600 hover:bg-green-700 text-white rounded-md font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex justify-center items-center gap-2"
            >
              {isImporting ? (
                <>
                  <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                  Restoring Backup...
                </>
              ) : (
                'Upload & Restore Backup'
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
