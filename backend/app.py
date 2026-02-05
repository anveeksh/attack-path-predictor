# app.py
# Flask API server for Attack Path Predictor
# Features: File Upload, PDF Export, Save/Load Projects

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import json
import os
from werkzeug.utils import secure_filename
from datetime import datetime
import io
from attack_path_predictor import AttackGraphBuilder, AttackPathPredictor, NetworkNode
from sample_data import get_sample_network, get_sample_attack_paths
from file_parser import ScanParser
from report_generator import PentestReportGenerator
import networkx as nx

app = Flask(__name__)
CORS(app)  # Enable CORS for React frontend

# Configuration
UPLOAD_FOLDER = 'uploads'
PROJECTS_FOLDER = 'projects'
ALLOWED_EXTENSIONS = {'xml', 'csv'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create necessary directories
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROJECTS_FOLDER, exist_ok=True)

# Global state
graph_builder = AttackGraphBuilder()
predictor = None

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'version': '1.0.0'})

@app.route('/api/upload/scan', methods=['POST'])
def upload_scan_file():
    """
    Upload and parse scan files (Nmap XML or Nessus CSV)
    Accepts: multipart/form-data with 'file' field
    Returns: Parsed network data
    """
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'error': 'Invalid file type. Please upload .xml or .csv files'}), 400
    
    filepath = None
    try:
        # Save file securely
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Parse file
        parser = ScanParser()
        
        if filename.endswith('.xml'):
            hosts = parser.parse_nmap_xml(filepath)
            scan_type = 'Nmap'
        elif filename.endswith('.csv'):
            hosts = parser.parse_nessus_csv(filepath)
            scan_type = 'Nessus'
        else:
            if filepath and os.path.exists(filepath):
                os.remove(filepath)
            return jsonify({'success': False, 'error': 'Unsupported file format'}), 400
        
        # Clean up uploaded file
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
        
        if not hosts:
            return jsonify({'success': False, 'error': 'No hosts found in scan file'}), 400
        
        return jsonify({
            'success': True,
            'scan_type': scan_type,
            'nodes': hosts,
            'count': len(hosts),
            'message': f'Successfully parsed {len(hosts)} hosts from {scan_type} scan'
        })
    
    except Exception as e:
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'success': False, 'error': f'Error parsing file: {str(e)}'}), 500

@app.route('/api/scan/network', methods=['POST'])
def scan_network():
    """Load sample network data"""
    try:
        discovered_nodes = get_sample_network()
        return jsonify({'success': True, 'nodes': discovered_nodes, 'count': len(discovered_nodes)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/scan/vulnerabilities', methods=['POST'])
def scan_vulnerabilities():
    """Scan for vulnerabilities"""
    data = request.json
    node_id = data.get('node_id')
    
    if not node_id:
        return jsonify({'success': False, 'error': 'node_id required'}), 400
    
    sample_vulnerabilities = [
        {
            'cve': 'CVE-2021-44228',
            'name': 'Log4Shell RCE',
            'cvss': 10.0,
            'exploitability': 0.95,
            'description': 'Remote code execution via Log4j',
            'remediation': 'Update Log4j to version 2.17.0+'
        }
    ]
    
    return jsonify({'success': True, 'node_id': node_id, 'vulnerabilities': sample_vulnerabilities})

@app.route('/api/graph/build', methods=['POST'])
def build_attack_graph():
    """Build the attack graph from discovered nodes"""
    global graph_builder, predictor
    
    data = request.json
    nodes_data = data.get('nodes', [])
    
    if not nodes_data:
        return jsonify({'success': False, 'error': 'No nodes provided'}), 400
    
    try:
        graph_builder = AttackGraphBuilder()
        
        for node_data in nodes_data:
            node = NetworkNode(
                id=node_data['id'],
                name=node_data['name'],
                ip=node_data['ip'],
                os=node_data['os'],
                services=node_data['services'],
                vulnerabilities=node_data.get('vulnerabilities', []),
                criticality=node_data.get('criticality', 'medium')
            )
            graph_builder.add_node(node)
        
        graph_builder.build_edges()
        predictor = AttackPathPredictor(graph_builder)
        
        stats = {
            'nodes': graph_builder.graph.number_of_nodes(),
            'edges': graph_builder.graph.number_of_edges(),
            'density': nx.density(graph_builder.graph)
        }
        
        return jsonify({'success': True, 'message': 'Attack graph built successfully', 'stats': stats})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/paths/predict', methods=['POST'])
def predict_attack_paths():
    """Predict attack paths from source to target"""
    global predictor
    
    if not predictor:
        return jsonify({'success': False, 'error': 'Graph not built. Call /api/graph/build first'}), 400
    
    data = request.json
    source = data.get('source')
    target = data.get('target')
    max_paths = data.get('max_paths', 5)
    
    if not source or not target:
        return jsonify({'success': False, 'error': 'source and target required'}), 400
    
    try:
        paths = predictor.find_optimal_paths(source, target, max_paths)
        
        paths_json = []
        for i, path in enumerate(paths, 1):
            paths_json.append({
                'id': i,
                'path': path.nodes,
                'techniques': path.techniques,
                'probability': path.probability,
                'difficulty': path.difficulty,
                'stealth': path.stealth_level,
                'estimated_time': path.estimated_time,
                'mitre_tactics': path.mitre_tactics
            })
        
        return jsonify({'success': True, 'paths': paths_json, 'count': len(paths_json)})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/graph/visualize', methods=['GET'])
def get_graph_visualization():
    """Get graph data for visualization"""
    global graph_builder
    
    if not graph_builder.graph.number_of_nodes():
        return jsonify({'success': False, 'error': 'No graph built'}), 400
    
    nodes = []
    for node_id, node_data in graph_builder.graph.nodes(data=True):
        nodes.append({
            'id': node_id,
            'label': node_data['name'],
            'ip': node_data['ip'],
            'os': node_data['os'],
            'criticality': node_data['criticality'],
            'vulns': len(node_data.get('vulnerabilities', []))
        })
    
    edges = []
    for source, target, edge_data in graph_builder.graph.edges(data=True):
        edges.append({
            'source': source,
            'target': target,
            'probability': edge_data['probability'],
            'techniques': edge_data.get('techniques', [])
        })
    
    return jsonify({'success': True, 'nodes': nodes, 'edges': edges})

@app.route('/api/export/pdf', methods=['POST'])
def export_pdf_report():
    """Generate PDF report from attack paths"""
    try:
        data = request.json
        paths = data.get('paths', [])
        hosts = data.get('hosts', [])
        
        if not paths:
            return jsonify({'success': False, 'error': 'No attack paths provided'}), 400
        
        generator = PentestReportGenerator()
        pdf_buffer = generator.generate_simple_report(paths, hosts)
        
        filename = f'attack_path_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
    
    except Exception as e:
        print(f"PDF Export Error: {str(e)}")
        return jsonify({'success': False, 'error': f'Error generating PDF: {str(e)}'}), 500

@app.route('/api/export/report', methods=['POST'])
def export_report():
    """Export attack path analysis as JSON report"""
    data = request.json
    paths = data.get('paths', [])
    
    report = {
        'title': 'Attack Path Analysis Report',
        'generated_at': datetime.now().isoformat(),
        'summary': f'Found {len(paths)} potential attack paths',
        'paths': paths,
        'recommendations': [
            'Implement network segmentation',
            'Patch critical vulnerabilities',
            'Enable multi-factor authentication',
            'Deploy EDR on critical assets'
        ]
    }
    return jsonify(report)

# ==================== PROJECT SAVE/LOAD ====================

@app.route('/api/project/save', methods=['POST'])
def save_project():
    """
    Save current project (network data + attack paths)
    Accepts: { "name": "project_name", "data": {...} }
    """
    try:
        data = request.json
        project_name = data.get('name', f'project_{datetime.now().strftime("%Y%m%d_%H%M%S")}')
        project_data = data.get('data', {})
        
        # Sanitize filename
        safe_name = secure_filename(project_name)
        if not safe_name.endswith('.json'):
            safe_name += '.json'
        
        filepath = os.path.join(PROJECTS_FOLDER, safe_name)
        
        # Add metadata
        project_data['metadata'] = {
            'name': project_name,
            'created_at': datetime.now().isoformat(),
            'version': '1.0.0'
        }
        
        # Save project
        with open(filepath, 'w') as f:
            json.dump(project_data, f, indent=2)
        
        return jsonify({
            'success': True,
            'message': f'Project saved as {safe_name}',
            'filename': safe_name
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error saving project: {str(e)}'}), 500

@app.route('/api/project/load', methods=['POST'])
def load_project():
    """
    Load saved project
    Accepts: { "filename": "project_name.json" }
    """
    try:
        data = request.json
        filename = secure_filename(data.get('filename', ''))
        
        if not filename:
            return jsonify({'success': False, 'error': 'Filename required'}), 400
        
        filepath = os.path.join(PROJECTS_FOLDER, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'success': False, 'error': 'Project not found'}), 404
        
        # Load project
        with open(filepath, 'r') as f:
            project_data = json.load(f)
        
        return jsonify({
            'success': True,
            'data': project_data,
            'message': f'Project {filename} loaded successfully'
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error loading project: {str(e)}'}), 500

@app.route('/api/project/list', methods=['GET'])
def list_projects():
    """List all saved projects"""
    try:
        projects = []
        
        for filename in os.listdir(PROJECTS_FOLDER):
            if filename.endswith('.json'):
                filepath = os.path.join(PROJECTS_FOLDER, filename)
                stat = os.stat(filepath)
                
                projects.append({
                    'filename': filename,
                    'name': filename.replace('.json', ''),
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                })
        
        # Sort by modified date (newest first)
        projects.sort(key=lambda x: x['modified'], reverse=True)
        
        return jsonify({
            'success': True,
            'projects': projects,
            'count': len(projects)
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error listing projects: {str(e)}'}), 500

@app.route('/api/project/delete', methods=['POST'])
def delete_project():
    """
    Delete saved project
    Accepts: { "filename": "project_name.json" }
    """
    try:
        data = request.json
        filename = secure_filename(data.get('filename', ''))
        
        if not filename:
            return jsonify({'success': False, 'error': 'Filename required'}), 400
        
        filepath = os.path.join(PROJECTS_FOLDER, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'success': False, 'error': 'Project not found'}), 404
        
        # Delete project
        os.remove(filepath)
        
        return jsonify({
            'success': True,
            'message': f'Project {filename} deleted successfully'
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error deleting project: {str(e)}'}), 500

if __name__ == '__main__':
    print("=" * 60)
    print("🎯 Attack Path Predictor API Server")
    print("=" * 60)
    print("Starting server on http://localhost:5001")
    print("API Documentation: http://localhost:5001/api/health")
    print("=" * 60)
    print("\n📁 File Upload Feature")
    print("   - Formats: Nmap XML (.xml), Nessus CSV (.csv)")
    print("   - Max size: 16MB")
    print("\n📄 PDF Export Feature")
    print("   - Endpoint: POST /api/export/pdf")
    print("\n💾 Project Save/Load Feature")
    print("   - Projects folder: ./projects/")
    print("   - Save: POST /api/project/save")
    print("   - Load: POST /api/project/load")
    print("   - List: GET /api/project/list")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5001, debug=True)