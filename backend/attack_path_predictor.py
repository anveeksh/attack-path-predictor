# attack_path_predictor.py
# Core backend for AI-Powered Attack Path Predictor

import networkx as nx
import numpy as np
from typing import List, Dict, Tuple
from dataclasses import dataclass
import json

@dataclass
class NetworkNode:
    """Represents a network asset"""
    id: str
    name: str
    ip: str
    os: str
    services: List[str]
    vulnerabilities: List[Dict]
    criticality: str
    access_level: str = "none"  # none, user, admin, system

@dataclass
class AttackPath:
    """Represents a predicted attack path"""
    nodes: List[str]
    techniques: List[str]
    probability: float
    difficulty: str
    stealth_level: str
    estimated_time: str
    mitre_tactics: List[str]

class AttackGraphBuilder:
    """Builds and analyzes attack graphs using NetworkX"""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.vulnerability_db = self._load_vulnerability_database()
        
    def add_node(self, node: NetworkNode):
        """Add a network asset to the attack graph"""
        self.graph.add_node(
            node.id,
            name=node.name,
            ip=node.ip,
            os=node.os,
            services=node.services,
            vulnerabilities=node.vulnerabilities,
            criticality=node.criticality,
            access_level=node.access_level
        )
    
    def build_edges(self):
        """
        Build edges between nodes based on:
        1. Network connectivity
        2. Exploitable vulnerabilities
        3. Trust relationships
        """
        nodes = list(self.graph.nodes(data=True))
        
        for i, (node1_id, node1_data) in enumerate(nodes):
            for node2_id, node2_data in nodes[i+1:]:
                # Check if nodes can communicate
                if self._can_communicate(node1_data, node2_data):
                    # Calculate exploitation probability
                    prob = self._calculate_exploit_probability(
                        node1_data, node2_data
                    )
                    
                    if prob > 0:
                        # Add bidirectional edges with different weights
                        self.graph.add_edge(
                            node1_id, node2_id,
                            weight=1-prob,
                            probability=prob,
                            techniques=self._get_applicable_techniques(
                                node1_data, node2_data
                            )
                        )
    
    def _can_communicate(self, node1: Dict, node2: Dict) -> bool:
        """Check if two nodes can communicate based on network topology"""
        # Simplified: Check if IPs are in same subnet or DMZ -> Internal
        ip1_parts = node1['ip'].split('.')
        ip2_parts = node2['ip'].split('.')
        
        # Same /24 subnet
        if ip1_parts[:3] == ip2_parts[:3]:
            return True
        
        # DMZ (10.0.x.x) can reach Internal (192.168.x.x)
        if ip1_parts[0] == '10' and ip2_parts[0] == '192':
            return True
            
        return False
    
    def _calculate_exploit_probability(self, source: Dict, target: Dict) -> float:
        """
        Calculate probability of successful exploitation
        Based on:
        - Vulnerability severity and exploitability
        - Target OS and services
        - Security controls
        """
        base_probability = 0.0
        
        # Check for critical vulnerabilities
        for vuln in target.get('vulnerabilities', []):
            cvss = vuln.get('cvss', 0)
            exploitability = vuln.get('exploitability', 0.5)
            
            # CVSS 9.0+ with high exploitability
            if cvss >= 9.0 and exploitability > 0.7:
                base_probability = max(base_probability, 0.85)
            elif cvss >= 7.0 and exploitability > 0.6:
                base_probability = max(base_probability, 0.65)
            elif cvss >= 5.0:
                base_probability = max(base_probability, 0.40)
        
        # Adjust based on services
        risky_services = ['FTP:21', 'SMB:445', 'RDP:3389', 'MySQL:3306']
        for service in target.get('services', []):
            if service in risky_services:
                base_probability += 0.1
        
        # Adjust based on OS (older = more vulnerable)
        os_lower = target.get('os', '').lower()
        if 'windows 7' in os_lower or 'windows server 2008' in os_lower:
            base_probability += 0.15
        
        return min(base_probability, 0.95)  # Cap at 95%
    
    def _get_applicable_techniques(self, source: Dict, target: Dict) -> List[str]:
        """Get MITRE ATT&CK techniques applicable for this edge"""
        techniques = []
        
        for service in target.get('services', []):
            if 'HTTP' in service or 'HTTPS' in service:
                techniques.extend(['T1190 - Exploit Public-Facing Application',
                                 'T1059.007 - JavaScript'])
            if 'SMB' in service:
                techniques.extend(['T1021.002 - SMB/Windows Admin Shares',
                                 'T1550.002 - Pass the Hash'])
            if 'RDP' in service:
                techniques.append('T1021.001 - Remote Desktop Protocol')
            if 'MySQL' in service or 'SQL' in service:
                techniques.append('T1190 - SQL Injection')
        
        return techniques
    
    def _load_vulnerability_database(self) -> Dict:
        """Load historical vulnerability exploitation data"""
        # Simplified version - would load from actual database
        return {
            'CVE-2021-44228': {  # Log4Shell
                'cvss': 10.0,
                'exploitability': 0.95,
                'techniques': ['T1190', 'T1059'],
                'success_rate': 0.92
            },
            'CVE-2017-0144': {  # EternalBlue
                'cvss': 8.1,
                'exploitability': 0.88,
                'techniques': ['T1210'],
                'success_rate': 0.87
            }
        }

class AttackPathPredictor:
    """ML-based attack path prediction engine"""
    
    def __init__(self, graph_builder: AttackGraphBuilder):
        self.graph = graph_builder.graph
        self.historical_data = self._load_historical_attack_data()
    
    def find_optimal_paths(self, start_node: str, target_node: str, 
                          max_paths: int = 5) -> List[AttackPath]:
        """
        Find optimal attack paths using:
        1. Dijkstra's algorithm for shortest weighted path
        2. K-shortest paths for alternatives
        3. ML-based probability scoring
        """
        
        try:
            # Find k-shortest paths
            paths = list(nx.shortest_simple_paths(
                self.graph, start_node, target_node, weight='weight'
            ))[:max_paths]
            
            attack_paths = []
            for path_nodes in paths:
                attack_path = self._analyze_path(path_nodes)
                attack_paths.append(attack_path)
            
            # Sort by probability (highest first)
            attack_paths.sort(key=lambda x: x.probability, reverse=True)
            
            return attack_paths
            
        except nx.NetworkXNoPath:
            return []
    
    def _analyze_path(self, nodes: List[str]) -> AttackPath:
        """Analyze a path and calculate its properties"""
        
        # Calculate overall probability using chain rule
        total_probability = 1.0
        techniques = []
        mitre_tactics = []
        
        for i in range(len(nodes) - 1):
            edge_data = self.graph.get_edge_data(nodes[i], nodes[i+1])
            if edge_data:
                total_probability *= edge_data['probability']
                techniques.extend(edge_data.get('techniques', []))
        
        # Adjust probability based on path length (longer = less likely)
        path_length_penalty = 0.95 ** (len(nodes) - 2)
        total_probability *= path_length_penalty
        
        # Determine difficulty
        difficulty = self._calculate_difficulty(nodes)
        
        # Determine stealth level
        stealth = self._calculate_stealth(nodes, techniques)
        
        # Estimate time
        estimated_time = self._estimate_time(len(nodes), difficulty)
        
        # Map to MITRE tactics
        mitre_tactics = self._map_to_mitre_tactics(techniques)
        
        return AttackPath(
            nodes=[self.graph.nodes[n]['name'] for n in nodes],
            techniques=techniques,
            probability=total_probability,
            difficulty=difficulty,
            stealth_level=stealth,
            estimated_time=estimated_time,
            mitre_tactics=list(set(mitre_tactics))
        )
    
    def _calculate_difficulty(self, nodes: List[str]) -> str:
        """Calculate overall difficulty of attack path"""
        avg_cvss = 0
        vuln_count = 0
        
        for node in nodes[1:]:  # Skip start node
            node_data = self.graph.nodes[node]
            for vuln in node_data.get('vulnerabilities', []):
                avg_cvss += vuln.get('cvss', 5.0)
                vuln_count += 1
        
        if vuln_count == 0:
            return "High"
        
        avg_cvss /= vuln_count
        
        if avg_cvss >= 8.0:
            return "Low"
        elif avg_cvss >= 6.0:
            return "Medium"
        else:
            return "High"
    
    def _calculate_stealth(self, nodes: List[str], techniques: List[str]) -> str:
        """Calculate stealth level based on techniques used"""
        # Noisy techniques
        noisy = ['T1046', 'T1021.001', 'T1190']  # Port scan, RDP, web exploit
        
        noisy_count = sum(1 for t in techniques if any(n in t for n in noisy))
        
        if noisy_count >= 3:
            return "Low"
        elif noisy_count >= 1:
            return "Medium"
        else:
            return "High"
    
    def _estimate_time(self, path_length: int, difficulty: str) -> str:
        """Estimate time to execute attack path"""
        base_time = path_length * 30  # 30 min per hop
        
        if difficulty == "Low":
            base_time *= 0.5
        elif difficulty == "High":
            base_time *= 2
        
        hours = base_time / 60
        
        if hours < 1:
            return f"{int(base_time)} minutes"
        else:
            return f"{hours:.1f} hours"
    
    def _map_to_mitre_tactics(self, techniques: List[str]) -> List[str]:
        """Map techniques to MITRE ATT&CK tactics"""
        tactic_mapping = {
            'T1190': 'Initial Access',
            'T1059': 'Execution',
            'T1021': 'Lateral Movement',
            'T1550': 'Lateral Movement',
            'T1210': 'Lateral Movement',
            'T1046': 'Discovery'
        }
        
        tactics = []
        for technique in techniques:
            tech_id = technique.split(' - ')[0] if ' - ' in technique else technique
            base_id = tech_id.split('.')[0]  # Get base ID (e.g., T1021 from T1021.002)
            
            if base_id in tactic_mapping:
                tactics.append(tactic_mapping[base_id])
        
        return tactics
    
    def _load_historical_attack_data(self) -> List[Dict]:
        """Load historical attack data for ML training"""
        # This would load real data from CTF solutions, pentest reports, etc.
        return [
            {
                'path': ['dmz', 'db', 'dc'],
                'success': True,
                'time': 120,
                'techniques': ['sqli', 'pth']
            }
        ]

# Example usage
def main():
    # Initialize the system
    builder = AttackGraphBuilder()
    
    # Add sample network nodes
    dmz_web = NetworkNode(
        id='dmz_web',
        name='DMZ-WebServer',
        ip='10.0.1.10',
        os='Ubuntu 20.04',
        services=['HTTP:80', 'HTTPS:443'],
        vulnerabilities=[
            {'cve': 'CVE-2021-44228', 'cvss': 10.0, 'exploitability': 0.95}
        ],
        criticality='medium'
    )
    
    internal_db = NetworkNode(
        id='internal_db',
        name='Internal-DB',
        ip='192.168.1.50',
        os='Windows Server 2019',
        services=['MySQL:3306', 'RDP:3389'],
        vulnerabilities=[
            {'cve': 'CVE-2019-0708', 'cvss': 9.8, 'exploitability': 0.85}
        ],
        criticality='high'
    )
    
    domain_controller = NetworkNode(
        id='domain_controller',
        name='Domain-Controller',
        ip='192.168.1.5',
        os='Windows Server 2022',
        services=['LDAP:389', 'Kerberos:88'],
        vulnerabilities=[
            {'cve': 'CVE-2020-1472', 'cvss': 10.0, 'exploitability': 0.90}
        ],
        criticality='critical'
    )
    
    # Build the graph
    builder.add_node(dmz_web)
    builder.add_node(internal_db)
    builder.add_node(domain_controller)
    builder.build_edges()
    
    # Initialize predictor
    predictor = AttackPathPredictor(builder)
    
    # Find attack paths
    paths = predictor.find_optimal_paths('dmz_web', 'domain_controller')
    
    # Display results
    print("Attack Path Analysis Results")
    print("=" * 60)
    for i, path in enumerate(paths, 1):
        print(f"\nPath #{i}")
        print(f"Nodes: {' → '.join(path.nodes)}")
        print(f"Probability: {path.probability:.2%}")
        print(f"Difficulty: {path.difficulty}")
        print(f"Stealth: {path.stealth_level}")
        print(f"Estimated Time: {path.estimated_time}")
        print(f"MITRE Tactics: {', '.join(path.mitre_tactics)}")
        print(f"Techniques: {', '.join(path.techniques[:3])}...")

if __name__ == "__main__":
    main()