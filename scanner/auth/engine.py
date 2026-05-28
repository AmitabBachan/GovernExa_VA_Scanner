import hvac
import paramiko
import winrm
from typing import Dict, Any, List
from core.config import settings

class SecretManager:
    def __init__(self):
        # Initialize Vault client
        self.client = hvac.Client(
            url=settings.VAULT_URL,
            token=settings.VAULT_TOKEN
        )

    def get_credentials(self, target_ip: str) -> Dict[str, str]:
        """
        Retrieve credentials for a specific IP from the secret manager.
        """
        if not self.client.is_authenticated():
            print("Vault is not authenticated.")
            return {}
            
        try:
            # Assumes a kv secrets engine at 'secret/data/devices/{target_ip}'
            response = self.client.secrets.kv.v2.read_secret_version(
                path=f'devices/{target_ip}'
            )
            return response['data']['data']
        except Exception as e:
            print(f"Error retrieving credentials for {target_ip}: {e}")
            return {}

class AuthEngine:
    def __init__(self):
        self.secret_manager = SecretManager()

    def scan(self, target_ip: str, os_type: str = 'linux') -> Dict[str, Any]:
        """
        Perform an authenticated scan on the target.
        os_type can be 'linux' (SSH) or 'windows' (WinRM/WMI).
        """
        creds = self.secret_manager.get_credentials(target_ip)
        if not creds:
            return {"status": "failed", "reason": "No credentials found"}

        if os_type == 'linux':
            return self._scan_linux(target_ip, creds)
        elif os_type == 'windows':
            return self._scan_windows(target_ip, creds)
            
        return {"status": "failed", "reason": "Unknown OS type"}

    def _scan_linux(self, target_ip: str, creds: Dict[str, str]) -> Dict[str, Any]:
        results = {"os_details": "", "packages": [], "running_services": []}
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=target_ip,
                username=creds.get("username"),
                password=creds.get("password"),
                timeout=10
            )
            
            # Get OS details
            stdin, stdout, stderr = ssh.exec_command('uname -a')
            results['os_details'] = stdout.read().decode().strip()
            
            # Example package inventory for Debian/Ubuntu
            # In a real scanner, we'd detect the package manager (dpkg, rpm, pacman) first
            stdin, stdout, stderr = ssh.exec_command("dpkg-query -W -f='${Package} ${Version}\n'")
            packages = stdout.read().decode().strip().split('\n')
            results['packages'] = [{"name": p.split(' ')[0], "version": p.split(' ')[1]} for p in packages if ' ' in p]
            
            ssh.close()
        except Exception as e:
            print(f"SSH Auth scan error on {target_ip}: {e}")
            
        return results

    def _scan_windows(self, target_ip: str, creds: Dict[str, str]) -> Dict[str, Any]:
        results = {"os_details": "", "packages": [], "running_services": []}
        try:
            session = winrm.Session(
                target_ip,
                auth=(creds.get("username"), creds.get("password")),
                transport='ntlm'
            )
            
            # Get OS details
            r = session.run_cmd('systeminfo', ['/fo', 'csv'])
            if r.status_code == 0:
                results['os_details'] = "Windows details fetched" # Simplified
                
            # Get installed software via PowerShell
            ps_script = "Get-WmiObject -Class Win32_Product | Select-Object Name, Version | ConvertTo-Json"
            r = session.run_ps(ps_script)
            if r.status_code == 0:
                # Parse JSON output here
                pass
                
        except Exception as e:
            print(f"WinRM Auth scan error on {target_ip}: {e}")
            
        return results
