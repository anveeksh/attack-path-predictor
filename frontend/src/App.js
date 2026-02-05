import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Network, Shield, Target, TrendingUp, AlertTriangle, Upload, FileText, Download, Save, FolderOpen, Trash2, X } from 'lucide-react';

const API_BASE_URL = 'http://localhost:5001/api';

function App() {
  const [activeTab, setActiveTab] = useState('network');
  const [networkData, setNetworkData] = useState([]);
  const [selectedNode, setSelectedNode] = useState(null);
  const [attackPaths, setAttackPaths] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  
  // File upload states
  const [uploadMode, setUploadMode] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadMessage, setUploadMessage] = useState('');
  
  // PDF export state
  const [isExporting, setIsExporting] = useState(false);
  
  // Save/Load states
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [showLoadDialog, setShowLoadDialog] = useState(false);
  const [projectName, setProjectName] = useState('');
  const [savedProjects, setSavedProjects] = useState([]);
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    loadSampleNetwork();
    loadProjectsList();
  }, []);

  const loadSampleNetwork = async () => {
    setIsLoading(true);
    try {
      const sampleData = [
        { id: 'dmz_web', name: 'DMZ-WebServer', ip: '10.0.1.10', os: 'Ubuntu 20.04', services: ['HTTP:80', 'HTTPS:443'], criticality: 'medium', vulns: 3 },
        { id: 'internal_db', name: 'Internal-DB', ip: '192.168.1.50', os: 'Windows Server 2019', services: ['MySQL:3306', 'RDP:3389'], criticality: 'high', vulns: 5 },
        { id: 'workstation_01', name: 'Workstation-01', ip: '192.168.1.100', os: 'Windows 10', services: ['SMB:445'], criticality: 'low', vulns: 2 },
        { id: 'domain_controller', name: 'Domain-Controller', ip: '192.168.1.5', os: 'Windows Server 2022', services: ['LDAP:389', 'Kerberos:88'], criticality: 'critical', vulns: 1 },
        { id: 'file_server', name: 'File-Server', ip: '192.168.1.60', os: 'Windows Server 2016', services: ['SMB:445', 'FTP:21'], criticality: 'medium', vulns: 4 }
      ];
      setNetworkData(sampleData);
    } catch (error) {
      console.error('Error loading network:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const loadProjectsList = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/project/list`);
      if (response.data.success) {
        setSavedProjects(response.data.projects);
      }
    } catch (error) {
      console.error('Error loading projects list:', error);
    }
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    
    const validExtensions = ['xml', 'csv'];
    const fileExtension = file.name.split('.').pop().toLowerCase();
    
    if (!validExtensions.includes(fileExtension)) {
      setUploadMessage('❌ Invalid file type. Please upload .xml or .csv files');
      return;
    }
    
    setIsUploading(true);
    setUploadMessage('📤 Uploading and parsing scan results...');
    
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      const response = await axios.post(`${API_BASE_URL}/upload/scan`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      
      if (response.data.success) {
        const parsedNodes = response.data.nodes.map(node => ({
          ...node,
          vulns: node.vulnerabilities?.length || 0
        }));
        
        setNetworkData(parsedNodes);
        setUploadMessage(`✅ ${response.data.message}`);
        setUploadMode(false);
        
        setTimeout(() => { setUploadMessage(''); }, 5000);
      }
    } catch (error) {
      console.error('Upload error:', error);
      setUploadMessage(`❌ Error: ${error.response?.data?.error || 'Failed to upload file'}`);
    } finally {
      setIsUploading(false);
      event.target.value = null;
    }
  };

  const exportToPDF = async () => {
    if (attackPaths.length === 0) {
      alert('No attack paths to export. Generate paths first.');
      return;
    }
    
    setIsExporting(true);
    
    try {
      const response = await axios.post(
        `${API_BASE_URL}/export/pdf`,
        { paths: attackPaths, hosts: networkData },
        { responseType: 'blob' }
      );
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `attack_path_report_${Date.now()}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
    } catch (error) {
      console.error('Error exporting PDF:', error);
      alert('Failed to export PDF report');
    } finally {
      setIsExporting(false);
    }
  };

  const saveProject = async () => {
    if (!projectName.trim()) {
      alert('Please enter a project name');
      return;
    }
    
    setIsSaving(true);
    
    try {
      const projectData = {
        networkData,
        attackPaths,
        timestamp: new Date().toISOString()
      };
      
      const response = await axios.post(`${API_BASE_URL}/project/save`, {
        name: projectName,
        data: projectData
      });
      
      if (response.data.success) {
        alert(`✅ ${response.data.message}`);
        setShowSaveDialog(false);
        setProjectName('');
        loadProjectsList();
      }
    } catch (error) {
      console.error('Error saving project:', error);
      alert(`❌ Error: ${error.response?.data?.error || 'Failed to save project'}`);
    } finally {
      setIsSaving(false);
    }
  };

  const loadProject = async (filename) => {
    try {
      const response = await axios.post(`${API_BASE_URL}/project/load`, { filename });
      
      if (response.data.success) {
        const projectData = response.data.data;
        setNetworkData(projectData.networkData || []);
        setAttackPaths(projectData.attackPaths || []);
        setShowLoadDialog(false);
        alert(`✅ ${response.data.message}`);
      }
    } catch (error) {
      console.error('Error loading project:', error);
      alert(`❌ Error: ${error.response?.data?.error || 'Failed to load project'}`);
    }
  };

  const deleteProject = async (filename) => {
    if (!window.confirm(`Delete project "${filename}"? This cannot be undone.`)) {
      return;
    }
    
    try {
      const response = await axios.post(`${API_BASE_URL}/project/delete`, { filename });
      
      if (response.data.success) {
        alert(`✅ ${response.data.message}`);
        loadProjectsList();
      }
    } catch (error) {
      console.error('Error deleting project:', error);
      alert(`❌ Error: ${error.response?.data?.error || 'Failed to delete project'}`);
    }
  };

  const generateAttackPaths = async () => {
    setIsScanning(true);
    
    try {
      await axios.post(`${API_BASE_URL}/graph/build`, { nodes: networkData });

      const response = await axios.post(`${API_BASE_URL}/paths/predict`, {
        source: networkData[0]?.id || 'dmz_web',
        target: networkData.find(n => n.criticality === 'critical')?.id || 'domain_controller',
        max_paths: 5
      });

      if (response.data.success) {
        setAttackPaths(response.data.paths);
        setActiveTab('paths');
      }
    } catch (error) {
      console.error('Error generating paths:', error);
      
      const samplePaths = [
        { id: 1, path: ['DMZ-WebServer', 'Internal-DB', 'Domain-Controller'], probability: 0.87, techniques: ['SQLi → RCE', 'Pass-the-Hash', 'DCSync'], difficulty: 'Medium', stealth: 'Low', estimated_time: '2.5 hours' },
        { id: 2, path: ['DMZ-WebServer', 'Workstation-01', 'File-Server', 'Domain-Controller'], probability: 0.72, techniques: ['Webshell Upload', 'Credential Dumping', 'Lateral Movement', 'Golden Ticket'], difficulty: 'High', stealth: 'High', estimated_time: '4.0 hours' },
        { id: 3, path: ['DMZ-WebServer', 'Internal-DB', 'File-Server', 'Domain-Controller'], probability: 0.65, techniques: ['SQL Injection', 'Privilege Escalation', 'SMB Relay', 'DCSync'], difficulty: 'Medium', stealth: 'Medium', estimated_time: '3.0 hours' }
      ];
      setAttackPaths(samplePaths);
      setActiveTab('paths');
    } finally {
      setIsScanning(false);
    }
  };

  const getCriticalityColor = (level) => {
    const colors = {
      critical: 'bg-red-100 text-red-800 border-red-300',
      high: 'bg-orange-100 text-orange-800 border-orange-300',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-300',
      low: 'bg-green-100 text-green-800 border-green-300'
    };
    return colors[level] || colors.medium;
  };

  const getProbabilityColor = (prob) => {
    if (prob >= 0.8) return 'text-red-600';
    if (prob >= 0.6) return 'text-orange-600';
    return 'text-yellow-600';
  };

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header with Save/Load Buttons */}
        <div className="mb-8 flex justify-between items-start">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <Target className="text-red-500" size={32} />
              <h1 className="text-3xl font-bold">Attack Path Predictor</h1>
            </div>
            <p className="text-gray-400">AI-powered penetration testing path analysis using graph theory and machine learning</p>
          </div>
          
          <div className="flex gap-2">
            <button onClick={() => setShowSaveDialog(true)} className="bg-purple-600 hover:bg-purple-700 px-4 py-2 rounded-lg font-medium transition-colors flex items-center gap-2">
              <Save size={18} />
              Save
            </button>
            <button onClick={() => { setShowLoadDialog(true); loadProjectsList(); }} className="bg-indigo-600 hover:bg-indigo-700 px-4 py-2 rounded-lg font-medium transition-colors flex items-center gap-2">
              <FolderOpen size={18} />
              Load
            </button>
          </div>
        </div>

        {/* Save Dialog */}
        {showSaveDialog && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4">
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold">Save Project</h2>
                <button onClick={() => setShowSaveDialog(false)} className="text-gray-400 hover:text-white">
                  <X size={24} />
                </button>
              </div>
              
              <input
                type="text"
                value={projectName}
                onChange={(e) => setProjectName(e.target.value)}
                placeholder="Enter project name..."
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white mb-4 focus:outline-none focus:border-purple-500"
                onKeyPress={(e) => e.key === 'Enter' && saveProject()}
              />
              
              <div className="flex gap-2">
                <button onClick={saveProject} disabled={isSaving} className="flex-1 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 px-4 py-2 rounded-lg font-medium transition-colors">
                  {isSaving ? 'Saving...' : 'Save'}
                </button>
                <button onClick={() => setShowSaveDialog(false)} className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg font-medium transition-colors">
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Load Dialog */}
        {showLoadDialog && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-gray-800 rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto">
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold">Load Project</h2>
                <button onClick={() => setShowLoadDialog(false)} className="text-gray-400 hover:text-white">
                  <X size={24} />
                </button>
              </div>
              
              {savedProjects.length === 0 ? (
                <div className="text-center py-8 text-gray-400">
                  <FolderOpen size={48} className="mx-auto mb-3 opacity-50" />
                  <p>No saved projects found</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {savedProjects.map((project) => (
                    <div key={project.filename} className="bg-gray-700 rounded-lg p-4 flex justify-between items-center hover:bg-gray-650 transition-colors">
                      <div>
                        <h3 className="font-semibold">{project.name}</h3>
                        <p className="text-sm text-gray-400">Modified: {project.modified}</p>
                      </div>
                      <div className="flex gap-2">
                        <button onClick={() => loadProject(project.filename)} className="bg-indigo-600 hover:bg-indigo-700 px-3 py-1 rounded text-sm font-medium transition-colors">
                          Load
                        </button>
                        <button onClick={() => deleteProject(project.filename)} className="bg-red-600 hover:bg-red-700 px-3 py-1 rounded text-sm font-medium transition-colors">
                          <Trash2 size={16} />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Navigation Tabs - Only 2 Tabs */}
        <div className="flex gap-2 mb-6 border-b border-gray-700">
          <button onClick={() => setActiveTab('network')} className={`px-4 py-2 font-medium transition-colors ${activeTab === 'network' ? 'text-red-500 border-b-2 border-red-500' : 'text-gray-400 hover:text-gray-200'}`}>
            <Network className="inline mr-2" size={18} />
            Network Discovery
          </button>
          <button onClick={() => setActiveTab('paths')} className={`px-4 py-2 font-medium transition-colors ${activeTab === 'paths' ? 'text-red-500 border-b-2 border-red-500' : 'text-gray-400 hover:text-gray-200'}`}>
            <TrendingUp className="inline mr-2" size={18} />
            Attack Paths
          </button>
        </div>

        {/* Network Discovery Tab */}
        {activeTab === 'network' && (
          <div>
            {uploadMessage && (
              <div className={`mb-4 p-4 rounded-lg ${uploadMessage.startsWith('✅') ? 'bg-green-900/30 border border-green-500 text-green-400' : uploadMessage.startsWith('❌') ? 'bg-red-900/30 border border-red-500 text-red-400' : 'bg-blue-900/30 border border-blue-500 text-blue-400'}`}>
                {uploadMessage}
              </div>
            )}

            <div className="bg-gray-800 rounded-lg p-4 mb-4">
              <div className="flex justify-between items-center">
                <div>
                  <h3 className="font-semibold mb-1 flex items-center gap-2">
                    <FileText size={20} />
                    Data Source
                  </h3>
                  <p className="text-sm text-gray-400">
                    {uploadMode ? 'Upload your scan results (Nmap/Nessus)' : `Using ${networkData.length > 5 ? 'uploaded' : 'sample'} data - ${networkData.length} hosts`}
                  </p>
                </div>
                <button onClick={() => { setUploadMode(!uploadMode); setUploadMessage(''); }} className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg font-medium transition-colors flex items-center gap-2">
                  {uploadMode ? <>← Back to Sample Data</> : <><Upload size={18} />Upload Scan Results</>}
                </button>
              </div>
              
              {uploadMode && (
                <div className="mt-4 p-6 bg-gray-900 rounded-lg border-2 border-dashed border-gray-600">
                  <div className="text-center">
                    <input type="file" accept=".xml,.csv" onChange={handleFileUpload} disabled={isUploading} className="hidden" id="file-upload" />
                    <label htmlFor="file-upload" className={`cursor-pointer inline-flex items-center gap-2 px-6 py-3 rounded-lg font-medium transition-colors ${isUploading ? 'bg-gray-600 cursor-not-allowed' : 'bg-gray-700 hover:bg-gray-600'}`}>
                      {isUploading ? <><div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent"></div>Processing...</> : <><Upload size={20} />Choose File</>}
                    </label>
                    <p className="text-sm text-gray-400 mt-3">Supported formats: <strong>Nmap XML (.xml)</strong>, <strong>Nessus CSV (.csv)</strong></p>
                    
                    <div className="mt-4 p-4 bg-gray-800 rounded text-left max-w-xl mx-auto">
                      <p className="text-sm font-semibold mb-2 flex items-center gap-2">💡 How to get scan files:</p>
                      <ul className="text-xs text-gray-400 space-y-2">
                        <li className="flex items-start gap-2">
                          <span className="text-blue-400 font-mono">•</span>
                          <div>
                            <strong className="text-gray-300">Nmap:</strong> 
                            <code className="ml-2 bg-gray-900 px-2 py-1 rounded text-green-400">nmap -sV -oX scan.xml [target]</code>
                          </div>
                        </li>
                        <li className="flex items-start gap-2">
                          <span className="text-blue-400 font-mono">•</span>
                          <div><strong className="text-gray-300">Nessus:</strong> Export results as CSV from Nessus UI</div>
                        </li>
                      </ul>
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="bg-gray-800 rounded-lg p-6 mb-6">
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold">Discovered Assets</h2>
                <button onClick={generateAttackPaths} disabled={isScanning || networkData.length === 0} className="bg-red-600 hover:bg-red-700 disabled:bg-gray-600 px-4 py-2 rounded-lg font-medium transition-colors flex items-center gap-2">
                  {isScanning ? <><div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent"></div>Analyzing...</> : <><Shield size={18} />Generate Attack Paths</>}
                </button>
              </div>

              {networkData.length === 0 ? (
                <div className="text-center py-12 text-gray-400">
                  <Network size={64} className="mx-auto mb-4 opacity-50" />
                  <p>No network data loaded.</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-4">
                  {networkData.map(node => (
                    <div key={node.id} onClick={() => setSelectedNode(node)} className={`bg-gray-750 border-2 ${selectedNode?.id === node.id ? 'border-red-500' : 'border-gray-700'} rounded-lg p-4 cursor-pointer hover:border-gray-600 transition-colors`}>
                      <div className="flex justify-between items-start mb-3">
                        <div>
                          <h3 className="font-semibold text-lg mb-1">{node.name}</h3>
                          <p className="text-gray-400 text-sm">{node.ip} | {node.os}</p>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-xs font-medium border ${getCriticalityColor(node.criticality)}`}>
                          {node.criticality.toUpperCase()}
                        </span>
                      </div>
                      <div className="flex flex-wrap gap-2 mb-3">
                        {node.services.map((service, idx) => (
                          <span key={idx} className="bg-gray-700 px-2 py-1 rounded text-xs">{service}</span>
                        ))}
                      </div>
                      <div className="flex items-center gap-2 text-sm">
                        <AlertTriangle size={16} className="text-orange-500" />
                        <span className="text-gray-300">{node.vulns} vulnerabilities detected</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Attack Paths Tab */}
        {activeTab === 'paths' && (
          <div>
            {attackPaths.length === 0 ? (
              <div className="bg-gray-800 rounded-lg p-12 text-center">
                <Shield size={64} className="mx-auto text-gray-600 mb-4" />
                <h3 className="text-xl font-semibold mb-2">No Attack Paths Generated</h3>
                <p className="text-gray-400 mb-4">Click "Generate Attack Paths" in the Network Discovery tab</p>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="bg-gray-800 rounded-lg p-4 mb-6 flex justify-between items-center">
                  <div>
                    <h3 className="font-semibold mb-2">Analysis Summary</h3>
                    <p className="text-gray-400 text-sm">Found {attackPaths.length} potential attack paths</p>
                  </div>
                  <button onClick={exportToPDF} disabled={isExporting} className="bg-green-600 hover:bg-green-700 disabled:bg-gray-600 px-4 py-2 rounded-lg font-medium transition-colors flex items-center gap-2">
                    {isExporting ? <><div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent"></div>Generating...</> : <><Download size={18} />Export PDF</>}
                  </button>
                </div>

                {attackPaths.map(path => (
                  <div key={path.id} className="bg-gray-800 rounded-lg p-6 border-2 border-gray-700 hover:border-gray-600 transition-colors">
                    <div className="flex justify-between items-start mb-4">
                      <div>
                        <h3 className="text-lg font-semibold mb-1">Attack Path #{path.id}</h3>
                        <p className="text-gray-400 text-sm">{path.path.length - 1} hops to target</p>
                      </div>
                      <div className="text-right">
                        <div className={`text-2xl font-bold ${getProbabilityColor(path.probability)}`}>{(path.probability * 100).toFixed(0)}%</div>
                        <div className="text-xs text-gray-400">Success Probability</div>
                      </div>
                    </div>

                    <div className="bg-gray-900 rounded-lg p-4 mb-4">
                      <div className="flex items-center gap-2 overflow-x-auto">
                        {path.path.map((node, idx) => (
                          <React.Fragment key={idx}>
                            <div className="flex flex-col items-center min-w-fit">
                              <div className={`px-4 py-2 rounded-lg font-medium ${idx === 0 ? 'bg-blue-600' : idx === path.path.length - 1 ? 'bg-red-600' : 'bg-gray-700'}`}>{node}</div>
                              {idx < path.techniques.length && (<div className="text-xs text-gray-500 mt-1">{path.techniques[idx]}</div>)}
                            </div>
                            {idx < path.path.length - 1 && (<div className="text-gray-600 text-2xl">→</div>)}
                          </React.Fragment>
                        ))}
                      </div>
                    </div>

                    <div className="grid grid-cols-3 gap-4">
                      <div className="bg-gray-900 rounded p-3">
                        <div className="text-xs text-gray-400 mb-1">Difficulty</div>
                        <div className="font-semibold">{path.difficulty}</div>
                      </div>
                      <div className="bg-gray-900 rounded p-3">
                        <div className="text-xs text-gray-400 mb-1">Stealth Level</div>
                        <div className="font-semibold">{path.stealth}</div>
                      </div>
                      <div className="bg-gray-900 rounded p-3">
                        <div className="text-xs text-gray-400 mb-1">Techniques</div>
                        <div className="font-semibold">{path.techniques.length}</div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default App;