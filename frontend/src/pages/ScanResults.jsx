import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import ForceGraph2D from 'react-force-graph-2d';
import axios from 'axios';
import { AlertTriangle, Download, FileWarning, KeyRound, Radar, ScanSearch, Server, ShieldAlert, Wrench } from 'lucide-react';
import { API_BASE_URL, API_URL } from '../config/api.js';

const emptyGraph = { nodes: [], links: [] };

export default function ScanResults() {
  const { id } = useParams();
  const [results, setResults] = useState(null);
  const [graphData, setGraphData] = useState(emptyGraph);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [downloadingReport, setDownloadingReport] = useState(false);

  useEffect(() => {
    const fetchResults = async () => {
      try {
        const res = await axios.get(`${API_URL}/scans/${id}/results`);
        setResults(res.data);
        setGraphData(res.data.graph_data?.nodes?.length ? res.data.graph_data : emptyGraph);
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

  return (
    <div className="w-full max-w-7xl mx-auto py-4 space-y-6">
      <div className="flex flex-col xl:flex-row xl:items-start xl:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white uppercase tracking-widest font-mono">
            Operation Analysis <span className="text-cyber-blue">[{scan.target_domain}]</span>
          </h1>
          <p className="text-cyber-dim font-mono text-xs mt-1">
            Attack Surface Topology, JavaScript Intelligence, GraphQL Discovery, and Vulnerability Matrix
          </p>
        </div>
        <div className="flex flex-wrap gap-3">
          <span className={`px-4 py-2 rounded border font-mono text-xs uppercase tracking-widest ${scan.status === 'Completed' ? 'border-cyber-green text-cyber-green bg-cyber-green/10' : scan.status === 'Running' ? 'border-cyber-blue text-cyber-blue bg-cyber-blue/10' : 'border-cyber-pink text-cyber-pink bg-cyber-pink/10'}`}>
            {scan.status}
          </span>
          {reportDownloadUrl && (
            <button
              type="button"
              onClick={downloadReport}
              disabled={downloadingReport}
              className="px-4 py-2 rounded border border-cyber-blue text-cyber-blue hover:bg-cyber-blue hover:text-cyber-bg transition-colors font-mono text-xs uppercase tracking-widest flex items-center gap-2"
            >
              <Download className="w-4 h-4" /> {downloadingReport ? 'Downloading...' : 'Download Report'}
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
        <SummaryCard title="Subdomains" value={summary?.subdomains || 0} color="text-cyber-blue" />
        <SummaryCard title="Endpoints" value={summary?.endpoints || 0} color="text-cyber-green" />
        <SummaryCard title="Directories" value={summary?.directories || 0} color="text-cyber-purple" />
        <SummaryCard title="Vulnerabilities" value={summary?.vulnerabilities || 0} color="text-cyber-pink" />
        <SummaryCard title="Secrets" value={summary?.secrets || 0} color="text-yellow-400" />
        <SummaryCard title="GraphQL" value={summary?.graphql_findings || 0} color="text-cyber-blue" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <Panel
          title="Scan Scope"
          icon={<ScanSearch className="w-4 h-4 text-cyber-blue" />}
          emptyLabel="No scope metadata recorded."
          items={[
            { id: 'requested-target', primary: requestedTarget, secondary: 'Requested target', accent: 'target' },
            { id: 'discovery-root', primary: discoveryRoot, secondary: 'Discovery root', accent: 'scope' },
          ]}
        />

        <Panel
          title="Tool Status"
          icon={<Wrench className="w-4 h-4 text-cyber-purple" />}
          emptyLabel="No tool diagnostics recorded."
          items={Object.entries(toolStatus).map(([tool, status]) => ({
            id: tool,
            primary: tool,
            secondary: toolPaths[tool] || 'Path unavailable',
            accent: status,
          }))}
        />

        <Panel
          title="Runtime Signals"
          icon={<AlertTriangle className="w-4 h-4 text-cyber-pink" />}
          emptyLabel="No runtime warnings recorded."
          items={[
            ...missingTools.map((tool) => ({ id: `missing-${tool}`, primary: tool, secondary: 'Missing external tool', accent: 'missing' })),
            ...fallbackTools.map((tool) => ({ id: `fallback-${tool}`, primary: tool, secondary: 'Fallback mode active', accent: 'fallback' })),
            ...(scanError ? [{ id: 'scan-error', primary: scanError, secondary: 'Last scan error', accent: 'error' }] : []),
          ]}
        />
      </div>

      <div className="glass-panel rounded-lg overflow-hidden border border-cyber-blue/20 relative px-4 h-[520px]">
        <div className="absolute top-4 left-4 z-10 glass-panel p-4 rounded text-xs font-mono space-y-2 max-w-xs">
          <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-cyber-blue"></span> root domain</div>
          <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-cyber-purple"></span> subdomain</div>
          <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-cyber-green"></span> endpoint</div>
          <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-cyber-pink"></span> vulnerability</div>
          <div className="pt-2 text-cyber-dim leading-relaxed">
            Graph path: domain → subdomain → endpoint → vulnerability. Drag nodes around to inspect the blast radius.
          </div>
        </div>

        <ForceGraph2D
          graphData={graphData}
          nodeLabel={(node) => `${node.name}${node.severity ? ` (${node.severity})` : ''}`}
          nodeColor={node => {
            if (node.group === 1) return '#00f3ff'; // root
            if (node.group === 2) return '#b026ff'; // sub
            if (node.group === 3) return '#00ff66'; // endpoint
            return '#ff0055'; // vulns
          }}
          nodeRelSize={6}
          linkColor={() => 'rgba(143, 159, 178, 0.4)'}
          linkWidth={1}
          backgroundColor="rgba(10, 10, 15, 0)" // transparent blending
          width={graphWidth}
          height={520}
        />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <Panel
          title="Technologies"
          icon={<Server className="w-4 h-4 text-cyber-blue" />}
          emptyLabel="No technologies fingerprinted yet."
          items={technologies.map((item) => ({ id: item, primary: item, accent: 'Fingerprint' }))}
        />

        <Panel
          title="Subdomains"
          icon={<Radar className="w-4 h-4 text-cyber-purple" />}
          emptyLabel="No subdomains recorded."
          items={subdomains.map((item) => ({ id: item.id, primary: item.domain, secondary: item.technologies?.join(', '), accent: item.source }))}
        />

        <Panel
          title="Endpoints"
          icon={<FileWarning className="w-4 h-4 text-cyber-green" />}
          emptyLabel="No endpoints recorded."
          items={endpoints.map((item) => ({
            id: item.id,
            primary: item.url,
            secondary: [item.source, item.hidden_parameters?.length ? `params: ${item.hidden_parameters.join(', ')}` : null].filter(Boolean).join(' • '),
            accent: item.status_code ? String(item.status_code) : item.is_graphql ? 'GraphQL' : 'Live',
          }))}
        />

        <Panel
          title="Directories"
          icon={<Server className="w-4 h-4 text-cyber-purple" />}
          emptyLabel="No directories recorded."
          items={directories.map((item) => ({
            id: item.id,
            primary: item.url || item.path,
            secondary: item.source,
            accent: item.status_code ? String(item.status_code) : 'Path',
          }))}
        />

        <Panel
          title="GraphQL Findings"
          icon={<Radar className="w-4 h-4 text-cyber-blue" />}
          emptyLabel="No GraphQL endpoints detected."
          items={graphqlFindings.map((item) => ({
            id: item.id,
            primary: item.endpoint,
            secondary: item.notes,
            accent: item.introspection_enabled ? 'Introspection open' : 'Endpoint found',
          }))}
        />

        <Panel
          title="Secrets"
          icon={<KeyRound className="w-4 h-4 text-yellow-400" />}
          emptyLabel="No secrets detected in JavaScript assets."
          items={secrets.map((item) => ({
            id: item.id,
            primary: `${item.category} • ${item.value_preview || 'redacted'}`,
            secondary: item.location,
            accent: item.severity,
          }))}
        />
      </div>

      <div className="grid grid-cols-1 gap-6">
        <Panel
          title="Vulnerabilities"
          icon={<ShieldAlert className="w-4 h-4 text-cyber-pink" />}
          emptyLabel="No vulnerabilities recorded."
          items={vulnerabilities.map((item) => ({
            id: item.id,
            primary: `${item.description}`,
            secondary: [item.tool, item.matched_at || item.host].filter(Boolean).join(' • '),
            accent: item.severity,
          }))}
        />
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
