# sample_data.py
# Sample network data for testing

def get_sample_network():
    """Returns sample network topology for testing"""
    return [
        {
            'id': 'dmz_web',
            'name': 'DMZ-WebServer',
            'ip': '10.0.1.10',
            'os': 'Ubuntu 20.04',
            'services': ['HTTP:80', 'HTTPS:443', 'SSH:22'],
            'vulnerabilities': [
                {
                    'cve': 'CVE-2021-44228',
                    'name': 'Log4Shell',
                    'cvss': 10.0,
                    'exploitability': 0.95,
                    'description': 'Remote Code Execution in Log4j',
                    'remediation': 'Update Log4j to 2.17.0 or later'
                },
                {
                    'cve': 'CVE-2021-3156',
                    'name': 'Sudo Heap Overflow',
                    'cvss': 7.8,
                    'exploitability': 0.75,
                    'description': 'Local privilege escalation',
                    'remediation': 'Update sudo package'
                }
            ],
            'criticality': 'medium'
        },
        {
            'id': 'internal_db',
            'name': 'Internal-Database',
            'ip': '192.168.1.50',
            'os': 'Windows Server 2019',
            'services': ['MySQL:3306', 'RDP:3389', 'SMB:445'],
            'vulnerabilities': [
                {
                    'cve': 'CVE-2019-0708',
                    'name': 'BlueKeep',
                    'cvss': 9.8,
                    'exploitability': 0.85,
                    'description': 'Remote Desktop Services RCE',
                    'remediation': 'Apply security patches'
                },
                {
                    'cve': 'CVE-2020-1472',
                    'name': 'Zerologon',
                    'cvss': 10.0,
                    'exploitability': 0.90,
                    'description': 'Netlogon privilege escalation',
                    'remediation': 'Install security updates'
                },
                {
                    'cve': 'CVE-2017-0144',
                    'name': 'EternalBlue',
                    'cvss': 8.1,
                    'exploitability': 0.88,
                    'description': 'SMBv1 Remote Code Execution',
                    'remediation': 'Disable SMBv1, apply patches'
                }
            ],
            'criticality': 'high'
        },
        {
            'id': 'workstation_01',
            'name': 'Workstation-01',
            'ip': '192.168.1.100',
            'os': 'Windows 10 Pro',
            'services': ['SMB:445', 'RDP:3389'],
            'vulnerabilities': [
                {
                    'cve': 'CVE-2021-34527',
                    'name': 'PrintNightmare',
                    'cvss': 8.8,
                    'exploitability': 0.82,
                    'description': 'Print Spooler RCE',
                    'remediation': 'Disable Print Spooler or apply patches'
                }
            ],
            'criticality': 'low'
        },
        {
            'id': 'file_server',
            'name': 'FileServer-01',
            'ip': '192.168.1.60',
            'os': 'Windows Server 2016',
            'services': ['SMB:445', 'FTP:21'],
            'vulnerabilities': [
                {
                    'cve': 'CVE-2017-0144',
                    'name': 'EternalBlue',
                    'cvss': 8.1,
                    'exploitability': 0.88,
                    'description': 'SMBv1 Remote Code Execution',
                    'remediation': 'Disable SMBv1'
                },
                {
                    'cve': 'CVE-2020-0796',
                    'name': 'SMBGhost',
                    'cvss': 10.0,
                    'exploitability': 0.90,
                    'description': 'SMBv3 compression RCE',
                    'remediation': 'Apply security patches'
                }
            ],
            'criticality': 'medium'
        },
        {
            'id': 'domain_controller',
            'name': 'Domain-Controller',
            'ip': '192.168.1.5',
            'os': 'Windows Server 2022',
            'services': ['LDAP:389', 'Kerberos:88', 'DNS:53', 'SMB:445'],
            'vulnerabilities': [
                {
                    'cve': 'CVE-2020-1472',
                    'name': 'Zerologon',
                    'cvss': 10.0,
                    'exploitability': 0.90,
                    'description': 'Netlogon elevation of privilege',
                    'remediation': 'Install August 2020 security updates'
                }
            ],
            'criticality': 'critical'
        }
    ]

def get_sample_attack_paths():
    """Returns sample pre-calculated attack paths"""
    return [
        {
            'id': 1,
            'path': ['DMZ-WebServer', 'Internal-Database', 'Domain-Controller'],
            'probability': 0.87,
            'techniques': ['T1190 - Exploit Public-Facing Application', 'T1550.002 - Pass the Hash', 'T1003.001 - DCSync'],
            'difficulty': 'Medium',
            'stealth': 'Low',
            'estimated_time': '2.5 hours',
            'mitre_tactics': ['Initial Access', 'Lateral Movement', 'Credential Access']
        },
        {
            'id': 2,
            'path': ['DMZ-WebServer', 'Workstation-01', 'FileServer-01', 'Domain-Controller'],
            'probability': 0.72,
            'techniques': ['T1190 - Web Exploit', 'T1078 - Valid Accounts', 'T1021.002 - SMB/Windows Admin Shares', 'T1558.003 - Golden Ticket'],
            'difficulty': 'High',
            'stealth': 'High',
            'estimated_time': '4.0 hours',
            'mitre_tactics': ['Initial Access', 'Lateral Movement', 'Persistence']
        },
        {
            'id': 3,
            'path': ['DMZ-WebServer', 'Internal-Database', 'FileServer-01', 'Domain-Controller'],
            'probability': 0.65,
            'techniques': ['T1190 - SQL Injection', 'T1068 - Privilege Escalation', 'T1021.002 - SMB Relay', 'T1003.001 - DCSync'],
            'difficulty': 'Medium',
            'stealth': 'Medium',
            'estimated_time': '3.0 hours',
            'mitre_tactics': ['Initial Access', 'Privilege Escalation', 'Lateral Movement']
        }
    ]