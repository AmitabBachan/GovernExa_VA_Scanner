import logging
import paramiko
import winrm
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class AuthScanEngine:
    """
    Performs authenticated deep scanning (SSH, WinRM).
    Requires credentials from the central CredentialsStore or external Secret Manager.
    """
    def __init__(self):
        pass

    def scan_linux(self, target_ip: str, credentials: Dict[str, str]) -> Dict[str, Any]:
        """
        Connects via SSH and extracts installed packages, users, and OS details.
        """
        results = {"os_details": "", "packages": [], "local_users": [], "patch_levels": []}
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Allow key-based or password authentication
            connect_kwargs = {
                "hostname": target_ip,
                "username": credentials.get("username"),
                "timeout": 10
            }
            if credentials.get("private_key"):
                import io
                pkey = paramiko.RSAKey.from_private_key(io.StringIO(credentials["private_key"]))
                connect_kwargs["pkey"] = pkey
            else:
                connect_kwargs["password"] = credentials.get("encrypted_password")
                
            ssh.connect(**connect_kwargs)
            
            stdin, stdout, stderr = ssh.exec_command('uname -a')
            results['os_details'] = stdout.read().decode().strip()
            
            # Debian/Ubuntu package inventory
            stdin, stdout, stderr = ssh.exec_command("dpkg-query -W -f='${Package} ${Version}\n'")
            packages = stdout.read().decode().strip().split('\n')
            
            for p in packages:
                if ' ' in p:
                    name, version = p.split(' ', 1)
                    results['packages'].append({"name": name, "version": version, "cpe": f"cpe:2.3:a:*:{name}:{version}:*:*:*:*:*:*:*"})
                    
            # Local Users
            stdin, stdout, stderr = ssh.exec_command("cat /etc/passwd | cut -d: -f1,5,7")
            users = stdout.read().decode().strip().split('\n')
            for u in users:
                if ':' in u:
                    parts = u.split(':')
                    if len(parts) >= 2:
                        results['local_users'].append({
                            "username": parts[0],
                            "description": parts[1],
                            "active": "nologin" not in parts[-1] and "false" not in parts[-1]
                        })

            ssh.close()
        except Exception as e:
            logger.error(f"SSH Auth scan error on {target_ip}: {e}")
            
        return results

    def scan_windows(self, target_ip: str, credentials: Dict[str, str]) -> Dict[str, Any]:
        """
        Connects via WinRM and extracts installed software, OS details, and users.
        """
        results = {"os_details": "", "packages": [], "local_users": [], "patch_levels": []}
        import json
        try:
            session = winrm.Session(
                target_ip,
                auth=(credentials.get("username"), credentials.get("encrypted_password")),
                transport='ntlm'
            )
            
            r = session.run_cmd('systeminfo', ['/fo', 'csv'])
            if r.status_code == 0:
                results['os_details'] = "Windows Host"
                
            # Packages
            ps_script = "Get-WmiObject -Class Win32_Product | Select-Object Name, Version | ConvertTo-Json"
            r = session.run_ps(ps_script)
            if r.status_code == 0:
                try:
                    pkgs = json.loads(r.std_out.decode('utf-8'))
                    if isinstance(pkgs, dict): pkgs = [pkgs]
                    for p in pkgs:
                        if isinstance(p, dict) and p.get("Name"):
                            results['packages'].append({"name": p.get("Name"), "version": p.get("Version", ""), "cpe": ""})
                except json.JSONDecodeError:
                    pass

            # Local Users
            ps_script_users = "Get-LocalUser | Select-Object Name, Description, Enabled | ConvertTo-Json"
            r = session.run_ps(ps_script_users)
            if r.status_code == 0:
                try:
                    users = json.loads(r.std_out.decode('utf-8'))
                    if isinstance(users, dict): users = [users]
                    for u in users:
                        if isinstance(u, dict) and u.get("Name"):
                            results['local_users'].append({
                                "username": u.get("Name"),
                                "description": u.get("Description", ""),
                                "active": u.get("Enabled", False)
                            })
                except json.JSONDecodeError:
                    pass

        except Exception as e:
            logger.error(f"WinRM Auth scan error on {target_ip}: {e}")
            
        return results
