# backend/file_parser.py
import xml.etree.ElementTree as ET
import pandas as pd
from typing import List, Dict

class ScanParser:
    """Parse various security scan file formats"""
    
    def parse_nmap_xml(self, file_path: str) -> List[Dict]:
        """Parse Nmap XML output"""
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            hosts = []
            
            for host in root.findall('.//host'):
                # Skip hosts that are down
                status = host.find('.//status')
                if status is None or status.get('state') != 'up':
                    continue
                
                # Get IP address
                ip_elem = host.find('.//address[@addrtype="ipv4"]')
                if ip_elem is None:
                    continue
                ip = ip_elem.get('addr')
                
                # Get hostname
                hostname_elem = host.find('.//hostname')
                hostname = hostname_elem.get('name') if hostname_elem is not None else f"host-{ip.replace('.', '-')}"
                
                # Get OS information
                os_match = host.find('.//osmatch')
                os_name = os_match.get('name') if os_match is not None else 'Unknown'
                
                # Get open ports and services
                services = []
                ports = host.findall('.//port')
                for port in ports:
                    state = port.find('.//state')
                    if state is not None and state.get('state') == 'open':
                        portid = port.get('portid')
                        service = port.find('.//service')
                        if service is not None:
                            service_name = service.get('name', 'unknown').upper()
                            services.append(f"{service_name}:{portid}")
                
                # Determine criticality
                criticality = self._determine_criticality(services, hostname)
                
                host_data = {
                    'id': f"host_{ip.replace('.', '_')}",
                    'name': hostname,
                    'ip': ip,
                    'os': os_name,
                    'services': services,
                    'vulnerabilities': [],
                    'criticality': criticality
                }
                
                hosts.append(host_data)
            
            print(f"Successfully parsed {len(hosts)} hosts from Nmap XML")
            return hosts
            
        except Exception as e:
            print(f"Error parsing Nmap XML: {e}")
            raise
    
    def parse_nessus_csv(self, file_path: str) -> List[Dict]:
        """Parse Nessus CSV export"""
        try:
            df = pd.read_csv(file_path)
            hosts_dict = {}
            
            for _, row in df.iterrows():
                host = str(row.get('Host', 'Unknown'))
                
                if host not in hosts_dict:
                    hosts_dict[host] = {
                        'id': f"host_{host.replace('.', '_')}",
                        'name': str(row.get('Host', host)),
                        'ip': host,
                        'os': 'Unknown',
                        'services': [],
                        'vulnerabilities': [],
                        'criticality': 'medium'
                    }
                
                # Add vulnerability
                if pd.notna(row.get('CVE')):
                    vuln = {
                        'cve': str(row.get('CVE', 'N/A')),
                        'name': str(row.get('Name', 'Unknown')),
                        'cvss': float(row.get('CVSS', 0)),
                        'exploitability': self._estimate_exploitability(float(row.get('CVSS', 0))),
                        'description': str(row.get('Description', '')),
                        'remediation': str(row.get('Solution', ''))
                    }
                    hosts_dict[host]['vulnerabilities'].append(vuln)
                
                # Add service
                port = row.get('Port')
                if pd.notna(port):
                    service_name = str(row.get('Name', 'unknown')).split()[0].upper()
                    service = f"{service_name}:{int(port)}"
                    if service not in hosts_dict[host]['services']:
                        hosts_dict[host]['services'].append(service)
            
            # Update criticality
            for host_data in hosts_dict.values():
                host_data['criticality'] = self._calculate_criticality(host_data)
            
            result = list(hosts_dict.values())
            print(f"Successfully parsed {len(result)} hosts from Nessus CSV")
            return result
            
        except Exception as e:
            print(f"Error parsing Nessus CSV: {e}")
            raise
    
    def _determine_criticality(self, services: List[str], hostname: str) -> str:
        hostname_lower = hostname.lower()
        
        if any(kw in hostname_lower for kw in ['dc', 'domain', 'controller']):
            return 'critical'
        
        high_risk = ['LDAP', 'KERBEROS', 'MSSQL', 'MYSQL']
        if any(any(srv in s for srv in high_risk) for s in services):
            return 'high'
        
        medium_risk = ['HTTP', 'HTTPS', 'SMB', 'RDP']
        if any(any(srv in s for srv in medium_risk) for s in services):
            return 'medium'
        
        return 'low'
    
    def _calculate_criticality(self, host_data: Dict) -> str:
        vulns = host_data.get('vulnerabilities', [])
        
        if not vulns:
            return self._determine_criticality(host_data['services'], host_data['name'])
        
        critical_count = sum(1 for v in vulns if v.get('cvss', 0) >= 9.0)
        high_count = sum(1 for v in vulns if 7.0 <= v.get('cvss', 0) < 9.0)
        
        if critical_count >= 2:
            return 'critical'
        elif critical_count >= 1 or high_count >= 3:
            return 'high'
        elif high_count >= 1:
            return 'medium'
        return 'low'
    
    def _estimate_exploitability(self, cvss: float) -> float:
        if cvss >= 9.0:
            return 0.9
        elif cvss >= 7.0:
            return 0.75
        elif cvss >= 5.0:
            return 0.6
        return 0.4