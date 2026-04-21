import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import ForceGraph2D from 'react-force-graph-2d';
import axios from 'axios';
import { AlertCircle, FileText, Activity, Layers, Code, Database, Key, ShieldAlert, Eye } from 'lucide-react';

export default function ScanResults() {
  const { id } = useParams();
  const [results, setResults] = useState(null);
  const [graphData, setGraphData] = useState(emptyGraph);
  const [loading, setLoading] = useState(true);
  
  // View modes: 'graph', 'report', 'findings'
  const [viewMode, setViewMode] = useState('graph');
  
  // Findings sub-tabs: 'infrastructure', 'js', 'graphql', 'secrets', 'vulnerabilities'
  const [activeTab, setActiveTab] = useState('vulnerabilities');

  useEffect(() => {
    const fetchResults = async () => {
      try {
        const res = await axios.get(`http://localhost:8000/api/scans/${id}`, {
          headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
        });
        const data = res.data;
        setScan(data);
        
        // ── Build Graph Topology ──────────────────────────────────────────────
        const nodes = [];
        const links = [];
        const target = data.target_domain;

        nodes.push({ id: target, name: target, group: 1, val: 20 });
        
        (data.subdomains || []).forEach(sub => {
            nodes.push({ id: sub.domain, name: sub.domain, group: 2, val: 15 });
            links.push({ source: target, target: sub.domain });
        });

        (data.endpoints || []).forEach(ep => {
            let parent = target;
            if (data.subdomains) {
                const matchingSub = data.subdomains.find(s => ep.url.includes(s.domain));
                if (matchingSub) parent = matchingSub.domain;
            }
            nodes.push({ id: ep.url, name: ep.url, group: 3, val: 10 });
            links.push({ source: parent, target: ep.url });
        });

        // Findings map to random endpoints for demo visual density
        (data.vulnerabilities || []).forEach(vuln => {
            let parent = target;
            if (data.endpoints && data.endpoints.length > 0) {
                parent = data.endpoints[Math.floor(Math.random() * data.endpoints.length)].url; 
            }
            const vId = `vuln_${vuln.id}`;
            nodes.push({ id: vId, name: vuln.description, group: 4, val: 8 });
            links.push({ source: parent, target: vId });
        });

        setGraphData({ nodes, links });
        setLoading(false);
      } catch (err) {
        console.error(err);
        setError(err.response?.data?.detail || 'Unable to decrypt scan artifacts.');
        setLoading(false);
      }
    };
    fetchResults();
  }, [id]);

  const downloadReport = async () => {
    if (!results?.report_download_url || downloadingReport) return;
    setDownloadingReport(true);
    try {
      const response = await axios.get(`${API_BASE_URL}${results.report_download_url}`, {
        responseType: 'blob',
      });
      const contentDisposition = response.headers['content-disposition'] || '';
      const fileNameMatch = contentDisposition.match(/filename\*?=(?:UTF-8''|\")?([^\";]+)/i);
      const fileName = fileNameMatch
        ? decodeURIComponent(fileNameMatch[1].replace(/\"/g, ''))
        : `${results?.scan?.target_domain || 'scan'}-report.txt`;
      const blobUrl = window.URL.createObjectURL(new Blob([response.data], { type: 'text/plain' }));
      const link = document.createElement('a');
      link.href = blobUrl;
      link.download = fileName;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(blobUrl);
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.detail || 'Unable to download report.');
    } finally {
      setDownloadingReport(false);
    }
  };

  if (loading) return <div className="text-cyber-blue font-mono p-10">Decrypting operational results...</div>;
  if (error || !results) return <div className="text-cyber-pink font-mono p-10">Error: {error || 'Scan record not found in system.'}</div>;

  const { scan, summary, subdomains, endpoints, directories, vulnerabilities, secrets, graphql_findings: graphqlFindings, report_download_url: reportDownloadUrl } = results;
  const technologies = summary?.technologies || [];
  const toolStatus = summary?.tool_status || {};
  const toolPaths = summary?.tool_paths || {};
  const requestedTarget = summary?.requested_target || scan.target_domain;
  const discoveryRoot = summary?.scan_scope || scan.target_domain;
  const missingTools = summary?.missing_tools || [];
  const fallbackTools = summary?.fallback_tools || [];
  const scanError = summary?.error || null;
  const graphWidth = typeof window !== 'undefined' ? Math.max(280, window.innerWidth - 120) : 900;

  // ── Helper to sort vulnerabilities by triage priority ─────────────────────
  const sortedVulns = [...(scan.vulnerabilities || [])].sort((a, b) => {
      const p = { "Critical": 4, "High": 3, "Medium": 2, "Low": 1 };
      return (p[b.priority] || 0) - (p[a.priority] || 0);
  });

  return (
    <div className="w-full h-[calc(100vh-100px)] flex flex-col">
      {/* ── Header & View Toggles ───────────────────────────────────────────── */}
      <div className="mb-4 flex justify-between items-end flex-wrap gap-4 px-4 w-full">
        <div>
            <h1 className="text-2xl font-bold text-white uppercase tracking-widest font-mono">
            Operation Analysis <span className="text-cyber-blue">[{scan.target_domain}]</span>
            </h1>
            <p className="text-cyber-dim font-mono text-xs mt-1">
            Status: {scan.status} | Initiated: {new Date(scan.created_at).toLocaleString()}
            </p>
        </div>
        <div className="flex gap-2 font-mono text-sm">
            <button 
                onClick={() => setViewMode('graph')}
                className={`flex items-center gap-2 px-4 py-2 border rounded transition-colors ${viewMode === 'graph' ? 'bg-cyber-blue/20 border-cyber-blue text-cyber-blue' : 'border-cyber-dim/30 text-cyber-dim hover:text-white hover:border-cyber-blue/50'}`}>
                <Activity size={16} /> Topology Graph
            </button>
            <button 
                onClick={() => setViewMode('findings')}
                className={`flex items-center gap-2 px-4 py-2 border rounded transition-colors ${viewMode === 'findings' ? 'bg-cyber-purple/20 border-cyber-purple text-cyber-purple' : 'border-cyber-dim/30 text-cyber-dim hover:text-white hover:border-cyber-purple/50'}`}>
                <Layers size={16} /> Findings Explorer
            </button>
            <button 
                onClick={() => setViewMode('report')}
                className={`flex items-center gap-2 px-4 py-2 border rounded transition-colors ${viewMode === 'report' ? 'bg-cyber-green/20 border-cyber-green text-cyber-green' : 'border-cyber-dim/30 text-cyber-dim hover:text-white hover:border-cyber-green/50'}`}>
                <FileText size={16} /> Exec Report
            </button>
        </div>
      </div>

      <div className="flex-grow glass-panel rounded-lg overflow-hidden border border-cyber-blue/20 relative mx-4 mb-4">
        
        {/* ── GRAPH MODE ────────────────────────────────────────────────────── */}
        {viewMode === 'graph' && (
            <div className="w-full h-full relative bg-gray-900/50">
                <div className="absolute top-4 left-4 z-10 glass-panel p-4 rounded text-xs font-mono space-y-2 pointer-events-none border border-cyber-blue/30 backdrop-blur-md bg-black/40">
                    <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-[#00f3ff] glow-blue"></span> Root Domain</div>
                    <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-[#b026ff] glow-purple"></span> Subdomain</div>
                    <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-[#00ff66] glow-green"></span> Endpoint</div>
                    <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-[#ff0055] glow-pink"></span> Vulnerability</div>
                </div>

                <ForceGraph2D
                    graphData={graphData}
                    nodeLabel="name"
                    nodeColor={node => {
                        if (node.group === 1) return '#00f3ff';
                        if (node.group === 2) return '#b026ff';
                        if (node.group === 3) return '#00ff66';
                        return '#ff0055';
                    }}
                    nodeRelSize={6}
                    linkColor={() => 'rgba(143, 159, 178, 0.4)'}
                    linkWidth={1}
                    backgroundColor="rgba(10, 10, 15, 0)"
                    width={window.innerWidth - 80}
                    height={window.innerHeight - 200}
                />
            </div>
        )}

        {/* ── REPORT MODE ───────────────────────────────────────────────────── */}
        {viewMode === 'report' && (
            <div className="p-8 font-mono max-w-5xl mx-auto space-y-8 h-full overflow-y-auto custom-scrollbar">
                <div className="text-center border-b border-cyber-dim/30 pb-6">
                    <h2 className="text-3xl font-bold text-white mb-2">Eartheye Reconnaissance Report</h2>
                    <p className="text-cyber-dim">Target: {scan.target_domain} | Full Platform Telemetry</p>
                </div>

                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                    <div className="p-4 bg-black/40 border border-cyber-purple/30 rounded flex flex-col items-center">
                        <span className="text-3xl text-cyber-purple font-bold glow-text-purple">{scan.subdomains?.length || 0}</span>
                        <span className="text-xs text-cyber-dim mt-2 tracking-wider">SUBDOMAINS</span>
                    </div>
                    <div className="p-4 bg-black/40 border border-cyber-green/30 rounded flex flex-col items-center">
                        <span className="text-3xl text-cyber-green font-bold glow-text-green">{scan.endpoints?.length || 0}</span>
                        <span className="text-xs text-cyber-dim mt-2 tracking-wider">ENDPOINTS</span>
                    </div>
                    <div className="p-4 bg-black/40 border border-yellow-500/30 rounded flex flex-col items-center">
                        <span className="text-3xl text-yellow-500 font-bold">{scan.javascript_files?.length || 0}</span>
                        <span className="text-xs text-cyber-dim mt-2 tracking-wider">JS FILES</span>
                    </div>
                    <div className="p-4 bg-black/40 border border-red-500/40 rounded flex flex-col items-center">
                         <span className="text-3xl text-red-500 font-bold glow-text-red">{scan.secrets?.length || 0}</span>
                         <span className="text-xs text-cyber-dim mt-2 tracking-wider">SECRETS</span>
                    </div>
                </div>

                <div>
                    <h3 className="text-xl text-cyber-blue border-b border-cyber-blue/30 pb-2 mb-4">Manual Pentest Preparation Pack</h3>
                    <div className="bg-black/30 p-6 rounded border border-cyber-blue/10 text-gray-300 leading-relaxed">
                        <p>This automated stage is complete. Proceed with manual verification using the findings explorer:</p>
                        <ul className="list-disc pl-5 mt-4 space-y-2 text-sm">
                            <li>Check <strong>Secrets Tab</strong> for critical exposed keys before they are rotated.</li>
                            <li>Analyze <strong>GraphQL Tab</strong> endpoints for schema leakage and query mutation testing.</li>
                            <li>Review <strong>JavaScript Intel</strong> for unlisted API routes that bypass WAF or CDN caches.</li>
                            <li>Triage the <strong>Vulnerabilities</strong> starting from <span className="text-red-400">Critical</span> items flagged as requiring manual review.</li>
                        </ul>
                    </div>
                </div>
            </div>
        )}

        {/* ── FINDINGS EXPLORER MODE ────────────────────────────────────────── */}
        {viewMode === 'findings' && (
            <div className="flex h-full">
                {/* Fixed Left Sidebar */}
                <div className="w-64 border-r border-cyber-dim/20 bg-black/40 p-4 font-mono">
                    <h2 className="text-white text-lg mb-6 uppercase tracking-wider border-b border-cyber-dim/30 pb-2">Intelligence</h2>
                    <ul className="space-y-2">
                        <li>
                            <button onClick={() => setActiveTab('visual')}
                                className={`w-full text-left px-3 py-2 rounded flex items-center justify-between transition-colors ${activeTab === 'visual' ? 'bg-[#00f3ff]/20 text-[#00f3ff] border border-[#00f3ff]/30' : 'text-cyber-dim hover:bg-white/5'}`}>
                                <span className="flex items-center gap-2"><Eye size={16}/> Visual Triage</span>
                                <span className="text-xs bg-black/50 px-1.5 py-0.5 rounded">{scan.endpoints?.filter(e => e.url.startsWith("http")).length || 0}</span>
                            </button>
                        </li>
                        <li>
                            <button onClick={() => setActiveTab('infrastructure')}
                                className={`w-full text-left px-3 py-2 rounded flex items-center justify-between transition-colors ${activeTab === 'infrastructure' ? 'bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30' : 'text-cyber-dim hover:bg-white/5'}`}>
                                <span className="flex items-center gap-2"><Database size={16}/> Infrastructure</span>
                                <span className="text-xs bg-black/50 px-1.5 py-0.5 rounded">{scan.endpoints?.length || 0}</span>
                            </button>
                        </li>
                        <li>
                            <button onClick={() => setActiveTab('js')}
                                className={`w-full text-left px-3 py-2 rounded flex items-center justify-between transition-colors ${activeTab === 'js' ? 'bg-yellow-500/20 text-yellow-500 border border-yellow-500/30' : 'text-cyber-dim hover:bg-white/5'}`}>
                                <span className="flex items-center gap-2"><Code size={16}/> JS Intel</span>
                                <span className="text-xs bg-black/50 px-1.5 py-0.5 rounded">{scan.javascript_files?.length || 0}</span>
                            </button>
                        </li>
                        <li>
                            <button onClick={() => setActiveTab('graphql')}
                                className={`w-full text-left px-3 py-2 rounded flex items-center justify-between transition-colors ${activeTab === 'graphql' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' : 'text-cyber-dim hover:bg-white/5'}`}>
                                <span className="flex items-center gap-2"><Layers size={16}/> GraphQL</span>
                                <span className="text-xs bg-black/50 px-1.5 py-0.5 rounded">{scan.graphql_endpoints?.length || 0}</span>
                            </button>
                        </li>
                        <li>
                            <button onClick={() => setActiveTab('secrets')}
                                className={`w-full text-left px-3 py-2 rounded flex items-center justify-between transition-colors ${activeTab === 'secrets' ? 'bg-red-500/20 text-red-500 border border-red-500/30' : 'text-cyber-dim hover:bg-white/5'}`}>
                                <span className="flex items-center gap-2"><Key size={16}/> Secrets</span>
                                <span className="text-xs bg-black/50 px-1.5 py-0.5 rounded">{scan.secrets?.length || 0}</span>
                            </button>
                        </li>
                        <li className="pt-4 border-t border-cyber-dim/20 mt-4">
                            <button onClick={() => setActiveTab('vulnerabilities')}
                                className={`w-full text-left px-3 py-2 rounded flex items-center justify-between transition-colors ${activeTab === 'vulnerabilities' ? 'bg-pink-500/20 text-pink-500 border border-pink-500/30' : 'text-cyber-dim hover:bg-white/5'}`}>
                                <span className="flex items-center gap-2"><ShieldAlert size={16}/> Triage Box</span>
                                <span className="text-xs bg-black/50 px-1.5 py-0.5 rounded">{scan.vulnerabilities?.length || 0}</span>
                            </button>
                        </li>
                    </ul>
                </div>

                {/* Right Content Area */}
                <div className="flex-1 overflow-y-auto p-8 bg-[#0a0f16] custom-scrollbar font-mono">
                    
                    {/* INFRASTRUCTURE */}
                    {activeTab === 'infrastructure' && (
                        <div>
                            <h3 className="text-2xl text-cyber-blue mb-6 border-b border-cyber-blue/30 pb-2">Exposed Perimeter</h3>
                            <div className="grid grid-cols-2 gap-8">
                                <div>
                                    <h4 className="text-cyber-purple mb-4">Subdomains</h4>
                                    <div className="space-y-2">
                                        {(scan.subdomains || []).map((s, i) => (
                                            <div key={i} className="bg-black/40 p-3 rounded border border-cyber-purple/20 flex justify-between">
                                                <span className="text-gray-300">
                                                    {s.domain}
                                                    {s.is_new && <span className="ml-2 text-[10px] bg-cyber-pink/20 text-cyber-pink px-1 rounded border border-cyber-pink/40 animate-pulse">NEW</span>}
                                                </span>
                                                <span className="text-xs text-cyber-green px-2 py-0.5 bg-cyber-green/10 rounded">ALIVE</span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                                <div>
                                    <h4 className="text-cyber-green mb-4">Endpoints</h4>
                                    <div className="space-y-2 max-h-[600px] overflow-y-auto pr-2 custom-scrollbar">
                                        {(scan.endpoints || []).map((e, i) => (
                                            <div key={i} className="bg-black/40 p-3 rounded border border-cyber-green/20 text-gray-300 truncate" title={e.url}>
                                                {e.url}
                                                {e.is_new && <span className="ml-2 text-[10px] bg-cyber-pink/20 text-cyber-pink px-1 rounded border border-cyber-pink/40 animate-pulse">NEW</span>}
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* JAVASCRIPT INTEL */}
                    {activeTab === 'js' && (
                        <div>
                            <h3 className="text-2xl text-yellow-500 mb-6 border-b border-yellow-500/30 pb-2">JavaScript App Intelligence</h3>
                            <div className="space-y-6">
                                {(scan.javascript_files || []).map((js, i) => {
                                    const eps = js.extracted_endpoints ? JSON.parse(js.extracted_endpoints) : [];
                                    const params = js.extracted_parameters ? JSON.parse(js.extracted_parameters) : [];
                                    return (
                                        <div key={i} className="bg-black/40 border border-yellow-500/20 rounded p-4">
                                            <div className="text-gray-200 border-b border-cyber-dim/20 pb-2 mb-4 truncate text-sm">
                                                <span className="text-yellow-500 mr-2">JS File:</span> {js.url}
                                            </div>
                                            <div className="grid grid-cols-2 gap-4 text-xs">
                                                <div className="bg-black/30 p-3 rounded">
                                                    <div className="text-cyber-dim mb-2 uppercase tracking-wide">Extracted Endpoints ({eps.length})</div>
                                                    <ul className="space-y-1 text-gray-400">
                                                        {eps.map((e, j) => <li key={j} className="text-cyber-green">{e}</li>)}
                                                        {eps.length === 0 && <li className="italic text-gray-600">None found</li>}
                                                    </ul>
                                                </div>
                                                <div className="bg-black/30 p-3 rounded">
                                                    <div className="text-cyber-dim mb-2 uppercase tracking-wide">Extracted Parameters ({params.length})</div>
                                                    <div className="flex flex-wrap gap-2 text-gray-400">
                                                        {params.map((p, j) => <span key={j} className="bg-white/5 px-2 py-0.5 rounded text-blue-300">{p}</span>)}
                                                        {params.length === 0 && <span className="italic text-gray-600">None found</span>}
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    )
                                })}
                                {(scan.javascript_files || []).length === 0 && (
                                    <p className="text-cyber-dim italic">No JavaScript intelligence gathered.</p>
                                )}
                            </div>
                        </div>
                    )}

                    {/* GRAPHQL */}
                    {activeTab === 'graphql' && (
                        <div>
                            <h3 className="text-2xl text-purple-400 mb-6 border-b border-purple-400/30 pb-2">GraphQL Exposure</h3>
                            <div className="space-y-4">
                                {(scan.graphql_endpoints || []).map((gql, i) => (
                                    <div key={i} className="bg-black/40 border border-purple-500/20 rounded p-4 flex justify-between items-center">
                                        <div className="text-gray-300">
                                            {gql.endpoint}
                                        </div>
                                        <div>
                                            {gql.has_introspection ? (
                                                <span className="bg-red-500/20 text-red-500 border border-red-500/50 px-3 py-1 text-xs rounded uppercase font-bold tracking-wider animate-pulse">
                                                    Introspection Enabled
                                                </span>
                                            ) : (
                                                <span className="bg-green-500/20 text-green-500 border border-green-500/50 px-3 py-1 text-xs rounded uppercase tracking-wider">
                                                    Secure Schema
                                                </span>
                                            )}
                                        </div>
                                    </div>
                                ))}
                                {(scan.graphql_endpoints || []).length === 0 && (
                                    <p className="text-cyber-dim italic">No GraphQL endpoints discovered.</p>
                                )}
                            </div>
                        </div>
                    )}

                    {/* SECRETS */}
                    {activeTab === 'secrets' && (
                        <div>
                            <h3 className="text-2xl text-red-500 mb-6 border-b border-red-500/30 pb-2">Exposed Credentials</h3>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                {(scan.secrets || []).map((sec, i) => (
                                    <div key={i} className="bg-black/40 border-l-4 border-red-500 rounded p-4 relative overflow-hidden group">
                                        <div className="absolute top-0 right-0 w-32 h-32 bg-red-500/5 rounded-full blur-2xl -mr-10 -mt-10 pointer-events-none"></div>
                                        <div className="flex justify-between items-start mb-1">
                                            <div className="text-xl text-red-400 font-bold">{sec.secret_type}</div>
                                            {sec.is_new && <span className="text-[10px] bg-cyber-pink/20 text-cyber-pink px-1 rounded border border-cyber-pink/40 animate-pulse">NEW LEAK</span>}
                                        </div>
                                        <div className="text-xs text-cyber-dim mb-4 truncate" title={sec.extracted_from}>Source: {sec.extracted_from}</div>
                                        <div className="bg-black/60 font-mono text-sm p-3 rounded text-green-400 border border-gray-800 break-all select-all">
                                            {sec.value}
                                        </div>
                                    </div>
                                ))}
                                {(scan.secrets || []).length === 0 && (
                                    <p className="text-cyber-dim italic">No secrets detected in current scope.</p>
                                )}
                            </div>
                        </div>
                    )}

                    {/* VULNERABILITIES (TRIAGE) */}
                    {activeTab === 'vulnerabilities' && (
                        <div>
                            <h3 className="text-2xl text-pink-500 mb-6 border-b border-pink-500/30 pb-2 flex items-center justify-between">
                                Priority Triage List
                                <span className="text-sm font-normal text-cyber-dim border border-cyber-dim/30 px-3 py-1 rounded">Sorted by Risk</span>
                            </h3>

                            <div className="space-y-4">
                                {sortedVulns.map((v, i) => {
                                    // Map priority to visual styles
                                    const pStyle = {
                                        "Critical": "bg-red-500/20 text-red-500 border-red-500/50 glow-border-red",
                                        "High": "bg-orange-500/20 text-orange-500 border-orange-500/50",
                                        "Medium": "bg-yellow-500/20 text-yellow-500 border-yellow-500/50",
                                    }[v.priority] || "bg-blue-500/20 text-blue-400 border-blue-500/50";

                                    return (
                                        <div key={i} className={`bg-black/40 border border-gray-800 rounded p-5 relative overflow-hidden transition-all hover:border-gray-600`}>
                                            <div className="flex justify-between items-start mb-3">
                                                <div className="text-lg text-white font-bold">
                                                    {v.description}
                                                    {v.is_new && <span className="ml-3 align-middle text-[10px] bg-cyber-pink/20 text-cyber-pink px-1 rounded border border-cyber-pink/40 animate-pulse">NEW FLAW</span>}
                                                </div>
                                                <div className={`px-3 py-1 rounded text-xs uppercase tracking-wider border font-bold ${pStyle}`}>
                                                    {v.priority} Priority
                                                </div>
                                            </div>
                                            
                                            <div className="flex gap-4 mb-4 text-xs font-mono">
                                                <span className="text-cyber-dim">Severity: <span className="text-gray-300">{v.severity.toUpperCase()}</span></span>
                                                <span className="text-cyber-dim">Confidence: <span className="text-gray-300">{v.confidence}</span></span>
                                                <span className="text-cyber-dim">Exposure: <span className="text-gray-300">{v.exposure_level}</span></span>
                                            </div>

                                            {v.manual_review_required && (
                                                <div className="inline-flex items-center gap-2 bg-pink-500/10 text-pink-400 border border-pink-500/30 px-3 py-1.5 rounded text-xs font-bold uppercase tracking-wide">
                                                    <AlertCircle size={14} /> Manual Pentest Verification Required
                                                </div>
                                            )}
                                        </div>
                                    )
                                })}
                                {sortedVulns.length === 0 && (
                                    <p className="text-cyber-dim italic">No actionable vulnerabilities found.</p>
                                )}
                            </div>
                        </div>
                    )}

                    {/* VISUAL TRIAGE */}
                    {activeTab === 'visual' && (
                        <div>
                            <h3 className="text-2xl text-[#00f3ff] mb-6 border-b border-[#00f3ff]/30 pb-2">Visual Triage Array</h3>
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                                {(scan.endpoints || []).filter(e => e.url.startsWith("http")).map((e, i) => {
                                    const safeName = e.url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_");
                                    const imgUrl = `http://localhost:8000/api/scans/static/${scan.target_domain}/${scan.id}/screenshots/${safeName}.png`;
                                    return (
                                        <div key={i} className="bg-black/40 border border-cyber-dim/30 rounded overflow-hidden group">
                                            <div className="bg-black border-b border-cyber-dim/30 p-2 text-xs font-mono text-gray-300 truncate" title={e.url}>
                                                {e.url}
                                            </div>
                                            <div className="relative aspect-video">
                                                <img 
                                                    src={imgUrl} 
                                                    alt={e.url} 
                                                    className="object-cover w-full h-full opacity-80 group-hover:opacity-100 transition-opacity"
                                                    onError={(ev) => { ev.target.parentElement.innerHTML = '<div class="flex items-center justify-center h-full text-cyber-dim text-xs italic">Capture offline //</div>'; }}
                                                />
                                            </div>
                                        </div>
                                    )
                                })}
                                {(scan.endpoints || []).filter(e => e.url.startsWith("http")).length === 0 && (
                                    <p className="text-cyber-dim italic">No HTTP targets identified for rendering.</p>
                                )}
                            </div>
                        </div>
                    )}

                </div>
            </div>
        )}
      </div>
    </div>
  );
}

function SummaryCard({ title, value, color }) {
  return (
    <div className="glass-panel rounded-lg p-4 border border-cyber-blue/10">
      <div className="text-cyber-dim font-mono text-xs uppercase tracking-[0.3em]">{title}</div>
      <div className={`mt-3 text-3xl font-bold ${color}`}>{value}</div>
    </div>
  );
}

function Panel({ title, icon, emptyLabel, items }) {
  return (
    <div className="glass-panel rounded-lg p-5 border border-cyber-blue/10">
      <div className="flex items-center gap-2 text-white font-mono uppercase tracking-wider text-sm mb-4">
        {icon}
        {title}
      </div>
      <div className="space-y-3 max-h-80 overflow-y-auto pr-1">
        {items.length === 0 && (
          <div className="border border-dashed border-cyber-dim/30 rounded p-4 text-cyber-dim font-mono text-xs">
            {emptyLabel}
          </div>
        )}
        {items.map((item) => (
          <div key={item.id} className="rounded-lg border border-cyber-dim/15 bg-cyber-bg/35 p-3">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="text-white font-mono break-all">{item.primary}</div>
                {item.secondary && <div className="text-cyber-dim text-xs font-mono mt-1 break-all">{item.secondary}</div>}
              </div>
              {item.accent && (
                <span className="shrink-0 px-2 py-1 rounded border border-cyber-blue/20 text-cyber-blue bg-cyber-blue/10 text-[10px] uppercase tracking-widest font-mono">
                  {item.accent}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
