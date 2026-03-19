import React, { useEffect, useState } from 'react';
import { fetchBlockchain, verifyChain } from '../services/api';
import { Link2, ShieldCheck, ShieldAlert, RefreshCw } from 'lucide-react';

export default function BlockchainPage() {
  const [chain, setChain]     = useState(null);
  const [verify, setVerify]   = useState(null);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);

  const load = async () => {
    setLoading(true);
    try {
      const [c, v] = await Promise.all([fetchBlockchain(), verifyChain()]);
      setChain(c.data);
      setVerify(v.data);
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  if (loading) return <div className="loading"><div className="spinner"/><span>Loading blockchain…</span></div>;

  const blocks = chain?.blocks || [];

  return (
    <div className="page">
      <div className="page-header" style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start'}}>
        <div>
          <h1 className="page-title">Blockchain Audit Log</h1>
          <p className="page-sub">
            Tamper-proof, immutable record of all intrusion detections.
            Each block is cryptographically linked to the previous.
          </p>
        </div>
        <button className="btn btn-outline" onClick={load}><RefreshCw size={14}/> Refresh</button>
      </div>

      {/* Chain status */}
      <div style={{
        display:'flex', alignItems:'center', gap:14, padding:'16px 20px',
        borderRadius:10, marginBottom:24,
        background: verify?.valid ? 'rgba(63,185,80,0.08)' : 'rgba(248,81,73,0.08)',
        border: `1px solid ${verify?.valid ? 'rgba(63,185,80,0.3)' : 'rgba(248,81,73,0.3)'}`,
      }}>
        {verify?.valid
          ? <ShieldCheck size={22} color="#3fb950"/>
          : <ShieldAlert size={22} color="#f85149"/>
        }
        <div>
          <p style={{fontWeight:700,color: verify?.valid ? '#3fb950' : '#f85149'}}>
            {verify?.message}
          </p>
          <p style={{fontSize:12,color:'var(--text-muted)',marginTop:2}}>
            {chain?.chain_length} blocks · Proof-of-Work difficulty: 2 leading zeros
          </p>
        </div>
      </div>

      {/* Block list — newest first */}
      <div>
        {[...blocks].reverse().map((block, i) => (
          <div key={block.index} className="block-card"
            style={block.index === 0 ? {borderColor:'rgba(88,166,255,0.4)'} : {}}>
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',
              cursor:'pointer'}} onClick={() => setExpanded(expanded === block.index ? null : block.index)}>
              <div style={{display:'flex',alignItems:'center',gap:12}}>
                <div style={{
                  width:36,height:36,borderRadius:8,
                  background: block.index === 0 ? 'rgba(88,166,255,0.15)' : 'rgba(248,81,73,0.1)',
                  display:'flex',alignItems:'center',justifyContent:'center',
                  fontWeight:700, fontSize:14,
                  color: block.index === 0 ? '#58a6ff' : '#f85149',
                  flexShrink:0,
                }}>
                  #{block.index}
                </div>
                <div>
                  <p style={{fontWeight:600,fontSize:13}}>
                    {block.index === 0 ? 'Genesis Block' : `Alert: ${block.data?.attack_category || 'Unknown'}`}
                  </p>
                  <p style={{fontSize:11,color:'var(--text-muted)'}}>
                    {new Date(block.timestamp * 1000).toLocaleString()} · Nonce: {block.nonce}
                  </p>
                </div>
              </div>

              <div style={{display:'flex',alignItems:'center',gap:12}}>
                {block.index > 0 && (
                  <span className={`badge badge-${
                    block.data?.severity === 'critical' ? 'critical' :
                    block.data?.severity === 'high' ? 'high' :
                    block.data?.severity === 'warning' ? 'warning' : 'info'
                  }`}>{block.data?.attack_category}</span>
                )}
                <span style={{fontSize:12,color:'var(--text-muted)'}}>
                  {expanded === block.index ? '▲' : '▼'}
                </span>
              </div>
            </div>

            {/* Expanded detail */}
            {expanded === block.index && (
              <div style={{marginTop:16,borderTop:'1px solid var(--border)',paddingTop:16}}>
                <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
                  <div>
                    <p style={{fontSize:11,color:'var(--text-muted)',marginBottom:4}}>Block Hash (SHA-256)</p>
                    <p className="block-hash">{block.hash}</p>
                  </div>
                  <div>
                    <p style={{fontSize:11,color:'var(--text-muted)',marginBottom:4}}>Previous Hash</p>
                    <p className="block-prev">{block.previous_hash}</p>
                  </div>
                </div>

                {block.index > 0 && (
                  <div style={{marginTop:14,
                    background:'var(--bg-secondary)',borderRadius:8,padding:14}}>
                    <p style={{fontSize:12,fontWeight:600,color:'var(--text-muted)',marginBottom:8}}>
                      Block Data
                    </p>
                    <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(180px,1fr))',gap:8}}>
                      {Object.entries(block.data).map(([k,v]) => (
                        typeof v !== 'object' ? (
                          <div key={k} style={{display:'flex',flexDirection:'column',gap:2}}>
                            <span style={{fontSize:10,color:'var(--text-muted)',textTransform:'uppercase'}}>{k}</span>
                            <span style={{fontSize:12,fontWeight:600,
                              fontFamily: ['alert_id','blockchain_block_index'].includes(k) ? 'monospace':'inherit'
                            }}>{String(v)}</span>
                          </div>
                        ) : null
                      ))}
                    </div>
                    {block.data.top_features && (
                      <div style={{marginTop:10}}>
                        <p style={{fontSize:10,color:'var(--text-muted)',textTransform:'uppercase',marginBottom:6}}>
                          Top SHAP Features
                        </p>
                        {block.data.top_features.map((f,i) => (
                          <div key={i} style={{fontSize:11,color:f.impact==='positive'?'#3fb950':'#f85149',marginBottom:2}}>
                            {f.feature}: {f.shap_value?.toFixed(4)}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Chain link visual */}
                {block.index > 0 && (
                  <div style={{marginTop:12,display:'flex',alignItems:'center',gap:8}}>
                    <Link2 size={12} color="var(--text-muted)"/>
                    <span style={{fontSize:11,color:'var(--text-muted)'}}>
                      Links to Block #{block.index - 1}
                    </span>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      {blocks.length === 1 && (
        <div style={{textAlign:'center',padding:40,color:'var(--text-muted)'}}>
          <p>Only the Genesis block exists. Run predictions to populate the chain.</p>
        </div>
      )}
    </div>
  );
}
