import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import ForceGraph2D from 'react-force-graph-2d';
import axios from 'axios';

// Mock data generator for the UI since real scanner requires binaries
const generateMockGraphData = (target) => {
  const nodes = [];
  const links = [];

  nodes.push({ id: target, name: target, group: 1, val: 20 });
  const subdomains = [`api.${target}`, `dev.${target}`, `admin.${target}`, `mail.${target}`];
  
  subdomains.forEach((sub, i) => {
    nodes.push({ id: sub, name: sub, group: 2, val: 15 });
    links.push({ source: target, target: sub });
    
    // endpoints
    for(let j=0; j<3; j++) {
      const ep = `${sub}/endpoint_${j}`;
      nodes.push({ id: ep, name: `/${j}`, group: 3, val: 10 });
      links.push({ source: sub, target: ep });

      // vulnerabilities on some
      if (Math.random() > 0.7) {
        const vuln = `${ep}_vuln`;
        nodes.push({ id: vuln, name: "SQLi / XSS", group: 4, val: 5 });
        links.push({ source: ep, target: vuln });
      }
    }
  });

  return { nodes, links };
};

export default function ScanResults() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchResults = async () => {
      try {
        const res = await axios.get(`http://localhost:8000/api/scans/${id}`);
        setScan(res.data);
        
        // In a real scenario, this endpoint would return the DB nodes
        // For demonstration purposes, we are generating mock structure mapped to the domain
        setGraphData(generateMockGraphData(res.data.target_domain));
        setLoading(false);
      } catch (err) {
        console.error(err);
        setLoading(false);
      }
    };
    fetchResults();
  }, [id]);

  if (loading) return <div className="text-cyber-blue font-mono p-10">Decrypting operational results...</div>;
  if (!scan) return <div className="text-cyber-pink font-mono p-10">Error: Scan record not found in system.</div>;

  return (
    <div className="w-full h-[calc(100vh-100px)] flex flex-col">
      <div className="mb-4">
        <h1 className="text-2xl font-bold text-white uppercase tracking-widest font-mono">
          Operation Analysis <span className="text-cyber-blue">[{scan.target_domain}]</span>
        </h1>
        <p className="text-cyber-dim font-mono text-xs mt-1">
          Attack Surface Topology & Vulnerability Matrix
        </p>
      </div>

      <div className="flex-grow glass-panel rounded-lg overflow-hidden border border-cyber-blue/20 relative pl-4 pr-4">
        <div className="absolute top-4 left-4 z-10 glass-panel p-4 rounded text-xs font-mono space-y-2">
          <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-cyber-blue"></span> root domain</div>
          <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-cyber-purple"></span> subdomain</div>
          <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-cyber-green"></span> endpoint</div>
          <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-cyber-pink"></span> vulnerability</div>
        </div>

        <ForceGraph2D
          graphData={graphData}
          nodeLabel="name"
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
          width={window.innerWidth - 100}
          height={window.innerHeight - 200}
        />
      </div>
    </div>
  );
}
