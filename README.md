# Attack Path Predictor

AI-powered penetration testing tool that predicts optimal attack paths in network environments using graph theory and machine learning.

## Overview

Attack Path Predictor is a cybersecurity tool designed to assist penetration testers and security professionals in identifying the most viable attack paths within a network infrastructure. By leveraging graph-based analysis and machine learning algorithms, the tool calculates probability scores for different attack vectors, helping security teams prioritize their efforts and understand potential threat scenarios.

## Key Features

- **Network Discovery**: Automated asset enumeration and service detection from security scan files
- **Vulnerability Assessment**: CVE-based vulnerability analysis with exploitability scoring
- **Graph-Based Analysis**: NetworkX-powered attack graph construction modeling network relationships
- **ML Predictions**: Probability-based path scoring using scikit-learn algorithms
- **MITRE ATT&CK Mapping**: Automatic correlation of attack techniques to the MITRE ATT&CK framework
- **File Import**: Support for Nmap XML and Nessus CSV scan file formats
- **PDF Report Generation**: Professional penetration testing reports with findings and recommendations
- **Project Management**: Save and load analysis sessions for continued work
- **Interactive Dashboard**: Real-time visualization of network assets and attack paths

## What Makes This Tool Unique

Traditional vulnerability scanners identify security weaknesses but do not provide guidance on which attack chains are most likely to succeed. Attack Path Predictor addresses this gap by:

- Calculating success probabilities before exploitation attempts
- Combining graph theory with machine learning for predictive analysis
- Providing actionable intelligence on optimal attack routes
- Mapping techniques to industry-standard frameworks (MITRE ATT&CK)
- Delivering data-driven insights for both offensive and defensive security operations

## Technical Architecture

### Backend
- **Framework**: Flask (Python 3.9+)
- **Graph Engine**: NetworkX for graph construction and path finding algorithms
- **Machine Learning**: scikit-learn for probability predictions
- **Report Generation**: ReportLab for PDF creation
- **File Parsing**: Custom parsers for Nmap XML and Nessus CSV formats

### Frontend
- **Framework**: React 18.2
- **Styling**: Tailwind CSS
- **HTTP Client**: Axios
- **Icons**: Lucide React
- **State Management**: React Hooks

### Algorithms
- Dijkstra's algorithm for shortest path calculation
- K-shortest paths for alternative route discovery
- Probabilistic scoring using vulnerability metrics (CVSS scores, exploitability ratings)
- Graph density analysis for network complexity assessment

## Prerequisites

- Python 3.9 or higher
- Node.js 16 or higher
- pip (Python package manager)
- npm (Node package manager)

## Installation

### Backend Setup

Navigate to the backend directory and install dependencies:
```bash
cd backend
pip install -r requirements.txt
```

### Frontend Setup

Navigate to the frontend directory and install dependencies:
```bash
cd frontend
npm install
```

## Running the Application

### Start Backend Server

From the backend directory:
```bash
cd backend
python app.py
```

The API server will start on http://localhost:5001

### Start Frontend Application

From the frontend directory (in a separate terminal):
```bash
cd frontend
npm start
```

The web interface will open automatically at http://localhost:3000

## Usage Guide

### 1. Network Data Input

**Option A: Use Sample Data**
- The tool loads with pre-configured sample network data for demonstration purposes
- Includes 5 hosts representing a typical enterprise network topology

**Option B: Upload Scan Files**
1. Click "Upload Scan Results" button
2. Select either Nmap XML or Nessus CSV file
3. Tool automatically parses and displays discovered assets

**Generating Scan Files:**

For Nmap XML:
```bash
nmap -sV -oX scan_results.xml [target_network]
```

For Nessus CSV:
- Export scan results as CSV format from Nessus web interface

### 2. Generate Attack Paths

1. Review discovered network assets in the Network Discovery tab
2. Click "Generate Attack Paths" button
3. Tool analyzes network topology and calculates optimal routes
4. Results appear in Attack Paths tab with probability rankings

### 3. Review Analysis Results

Each attack path displays:
- Success probability percentage (0-100%)
- Complete path from entry point to target
- MITRE ATT&CK techniques required at each step
- Difficulty rating (Low/Medium/High)
- Stealth level assessment
- Estimated time to execute
- Number of techniques required

### 4. Export Results

Click "Export PDF Report" to download a professional penetration testing report containing:
- Executive summary
- Network overview table
- Detailed attack path analysis
- Security recommendations prioritized by risk

### 5. Project Management

**Save Project:**
1. Click "Save" button in header
2. Enter project name
3. Project data stored for future access

**Load Project:**
1. Click "Load" button in header
2. Select from list of saved projects
3. Network data and attack paths restored

## API Documentation

### Endpoints

**Health Check**
```
GET /api/health
Response: {"status": "healthy", "version": "1.0.0"}
```

**Upload Scan File**
```
POST /api/upload/scan
Content-Type: multipart/form-data
Body: file (Nmap XML or Nessus CSV)
Response: {"success": true, "nodes": [...], "count": N}
```

**Build Attack Graph**
```
POST /api/graph/build
Content-Type: application/json
Body: {"nodes": [...]}
Response: {"success": true, "stats": {...}}
```

**Predict Attack Paths**
```
POST /api/paths/predict
Content-Type: application/json
Body: {"source": "node_id", "target": "node_id", "max_paths": 5}
Response: {"success": true, "paths": [...]}
```

**Export PDF Report**
```
POST /api/export/pdf
Content-Type: application/json
Body: {"paths": [...], "hosts": [...]}
Response: Binary PDF file
```

**Save Project**
```
POST /api/project/save
Content-Type: application/json
Body: {"name": "project_name", "data": {...}}
Response: {"success": true, "filename": "project.json"}
```

**Load Project**
```
POST /api/project/load
Content-Type: application/json
Body: {"filename": "project.json"}
Response: {"success": true, "data": {...}}
```

**List Projects**
```
GET /api/project/list
Response: {"success": true, "projects": [...]}
```

## Project Structure
```
attack-path-predictor/
├── backend/
│   ├── attack_path_predictor.py   # Core graph analysis engine
│   ├── app.py                      # Flask API server
│   ├── file_parser.py              # Nmap/Nessus file parsers
│   ├── report_generator.py         # PDF report generation
│   ├── sample_data.py              # Sample network data
│   ├── config.py                   # Configuration management
│   ├── requirements.txt            # Python dependencies
│   ├── .env                        # Environment variables
│   ├── projects/                   # Saved project files
│   └── uploads/                    # Temporary file uploads
├── frontend/
│   ├── public/
│   │   └── index.html             # HTML template
│   ├── src/
│   │   ├── App.js                 # Main React component
│   │   ├── index.js               # React entry point
│   │   └── index.css              # Global styles
│   └── package.json               # Node dependencies
├── README.md                       # This file
└── .gitignore                      # Git ignore rules
```

## How It Works

### 1. Network Graph Construction

The tool builds a directed graph representing the network topology where:
- Nodes represent network hosts (servers, workstations, network devices)
- Edges represent potential attack vectors based on network connectivity and vulnerabilities
- Edge weights calculated from CVSS scores, exploitability metrics, and service configurations

### 2. Probability Calculation

For each potential connection between hosts, the tool calculates exploitation probability using:
```
Base Probability = f(CVSS_score, exploitability_rating)
Adjusted Probability = Base + service_risk_bonus
Final Probability = min(Adjusted, 0.95)
```

### 3. Path Finding Algorithm

The tool uses Dijkstra's algorithm to find k-shortest paths from entry points to target assets. Path probability calculated using chain rule:
```
P(path) = P(edge_1) × P(edge_2) × ... × P(edge_n) × length_penalty
```

### 4. MITRE ATT&CK Mapping

Each edge is analyzed for applicable attack techniques based on:
- Target operating system
- Running services and open ports
- Known vulnerability types
- Common exploitation patterns

Techniques are mapped to their corresponding MITRE ATT&CK identifiers and tactics.

## Use Cases

### Red Team Operations
- Identify highest probability attack chains before engagement
- Plan attack strategy with data-driven decision making
- Estimate time requirements for complex attack scenarios
- Select stealthy vs. efficient paths based on engagement rules

### Blue Team Defense
- Understand attacker perspective on network vulnerabilities
- Prioritize remediation efforts based on exploitability
- Validate network segmentation effectiveness
- Test detection capabilities against predicted attack paths

### Vulnerability Management
- Move beyond simple CVSS scores to contextual risk assessment
- Understand vulnerability chaining and compound risks
- Prioritize patching based on attack path impact
- Measure security improvement after remediation

### Security Training
- Teach attack path concepts with visual examples
- Demonstrate real-world penetration testing methodology
- Provide hands-on learning with MITRE ATT&CK framework
- Build intuition for vulnerability exploitation

## Security Considerations

**Important**: This tool is designed for authorized security testing and research purposes only. Users must:

- Obtain proper written authorization before testing any network
- Comply with applicable laws and regulations
- Use the tool only on systems they own or have explicit permission to test
- Follow responsible disclosure practices for any findings

Unauthorized access to computer systems is illegal. The developers assume no liability for misuse of this tool.

## Limitations

- Probability calculations are estimates based on heuristics and may not reflect real-world conditions
- Does not account for human factors (social engineering, insider threats)
- Assumes no active defense mechanisms (IDS/IPS, SOC monitoring)
- Machine learning model requires training on historical data for optimal accuracy
- Network reachability assumptions may not reflect complex firewall configurations

## Future Enhancements

- Real-time network scanning integration with Nmap API
- Neo4j graph database for scalability with large networks
- Enhanced machine learning models trained on CTF and pentest datasets
- Interactive network graph visualization with zoom/pan controls
- MITRE ATT&CK Navigator heatmap generation
- Defensive recommendations engine
- Multi-user collaboration features
- Cloud environment support (AWS, Azure, GCP)
- Integration with threat intelligence feeds

## Contributing

This is an open-source research and educational project. Contributions are welcome through:

- Bug reports and feature requests via GitHub Issues
- Pull requests for code improvements
- Documentation enhancements
- Testing and validation feedback

## License

MIT License - See LICENSE file for details

## Author

**Anveeksh M Rao**  
Cybersecurity Graduate Student | Northeastern University  
Website: https://www.anveekshmrao.com  
GitHub: https://github.com/anveekshmrao

## Acknowledgments

- MITRE Corporation for the ATT&CK framework
- NetworkX development team for graph algorithms
- Open-source security community for tools and methodologies
- Academic research in automated penetration testing

## Citation

If you use this tool in academic research, please cite:
```
Rao, A.M. (2026). Attack Path Predictor: AI-Powered Penetration Testing Tool.
GitHub repository: https://github.com/anveekshmrao/attack-path-predictor
```

## Disclaimer

This tool is provided "as is" without warranty of any kind. The authors are not responsible for any damage or legal consequences resulting from the use or misuse of this software. Always ensure you have proper authorization before conducting security testing.

## Version History

### v1.0.0 (February 2026)
- Initial release
- Core attack path prediction engine
- Nmap and Nessus file import support
- PDF report generation
- Project save/load functionality
- React-based web interface
- RESTful API architecture

## Support

For questions, issues, or feature requests:
- Open an issue on GitHub
- Contact: [Your Email]
- Documentation: See README and code comments

---

Built with dedication for the cybersecurity community.
