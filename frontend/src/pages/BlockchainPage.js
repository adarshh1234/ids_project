import React, { useEffect, useState } from 'react';
import { fetchBlockchain, verifyChain } from '../services/api';
import { Link2, ShieldCheck, ShieldAlert, RefreshCw, Cpu } from 'lucide-react';

export default function BlockchainPage() {
  const [chain, setChain]       = useState(null);
  const [verify, setVerify]     = useState(null);
  const [loading, setLoading]   = useState(true);
  const [expanded, setExpanded] = useState(null);
  const [activeTab, setActiveTab] = useState('alerts');

  const load = async () => {
    setLoading(true);
    try {
      const [c, v] = await Promise.all([fetchBlockchain(), verifyChain()]);
      setChain(c.data);
      setVerify(v.data);
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  if (loading) return <div className="loading"><div className="spinner"/><span>Connecting to Ganache...</span></div>;

  const info   = chain?.network_info || {};
  const alerts = chain?.alerts || [];
  const txs    = chain?.transactions || [];

  return (
    <div className="page">
      <div className="page-header" style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start'}}>
        <div>
          <h1 className="page-title">Blockchain Audit Log</h1>
          <p className="page-sub"></p>
        </div>
        <button className="btn btn-outline" onClick={load}><RefreshCw size={14}/> Refresh</button>
      </div>

      {/* Network Stats */}
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(180px,1fr))',gap:16,marginBottom:24}}>
        {[
          {label:'Network',        value:'Ganache Ethereum',                              icon:'🔷', color:'#58a6ff'},
          {label:'Chain ID',       value:info.chain_id??'—',                              icon:'⛓️', color:'#bc8cff'},
          {label:'Block Number',   value:info.block_number??'—',                          icon:'📦', color:'#3fb950'},
          {label:'Alerts On-Chain',value:info.alert_count??0,                             icon:'🚨', color:'#f85149'},
          {label:'ETH Balance',    value:info.balance_eth?`${parseFloat(info.balance_eth).toFixed(3)} ETH`:'—', icon:'💎', color:'#e3b341'},
          {label:'Status',         value:info.connected?'Connected':'Disconnected',       icon:info.connected?'✅':'❌', color:info.connected?'#3fb950':'#f85149'},
        ].map(({label,value,icon,color}) => (
          <div className="stat-card" key={label}>
            <p style={{fontSize:18}}>{icon}</p>
            <p className="stat-label">{label}</p>
            <p style={{fontSize:15,fontWeight:700,color,marginTop:4}}>{String(value)}</p>
          </div>
        ))}
      </div>

      {/* Contract Address */}
      {info.contract_address && (
        <div style={{background:'rgba(88,166,255,0.07)',border:'1px solid rgba(88,166,255,0.2)',borderRadius:10,padding:'14px 18px',marginBottom:24}}>
          <div style={{display:'flex',alignItems:'center',gap:10}}>
            <Cpu size={14} color="#58a6ff"/>
            <span style={{fontSize:12,color:'var(--text-muted)'}}>Smart Contract (IDSAuditLog.sol)</span>
          </div>
          <p style={{fontFamily:'monospace',fontSize:13,color:'#58a6ff',marginTop:6,wordBreak:'break-all'}}>{info.contract_address}</p>
          <p style={{fontSize:11,color:'var(--text-muted)',marginTop:4}}>Deployed by: {info.account}</p>
        </div>
      )}

      {/* Verify Banner */}
      <div style={{display:'flex',alignItems:'center',gap:14,padding:'14px 18px',borderRadius:10,marginBottom:24,
        background:verify?.valid?'rgba(63,185,80,0.08)':'rgba(248,81,73,0.08)',
        border:`1px solid ${verify?.valid?'rgba(63,185,80,0.3)':'rgba(248,81,73,0.3)'}`}}>
        {verify?.valid?<ShieldCheck size={22} color="#3fb950"/>:<ShieldAlert size={22} color="#f85149"/>}
        <div>
          <p style={{fontWeight:700,color:verify?.valid?'#3fb950':'#f85149'}}>{verify?.message}</p>
          <p style={{fontSize:12,color:'var(--text-muted)',marginTop:2}}>
            {verify?.alert_count} alerts logged · Contract: {verify?.contract_address?.slice(0,20)}...
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div style={{display:'flex',gap:4,marginBottom:20}}>
        {[
          {key:'alerts',       label:`📋 On-Chain Alerts (${alerts.length})`},
          {key:'transactions', label:`⚡ Transactions (${txs.length})`},
        ].map(t => (
          <button key={t.key} onClick={() => setActiveTab(t.key)} className="btn" style={{
            background:activeTab===t.key?'rgba(88,166,255,0.15)':'transparent',
            color:activeTab===t.key?'#58a6ff':'var(--text-muted)',
            border:`1px solid ${activeTab===t.key?'rgba(88,166,255,0.4)':'var(--border)'}`,
          }}>{t.label}</button>
        ))}
      </div>

      {/* Alerts Tab */}
      {activeTab === 'alerts' && (
        <div>
          {[...alerts].reverse().map((alert, i) => {
            const borderColor = alert.attack_category==='DoS'?'#f85149':alert.attack_category==='Probe'?'#bc8cff':alert.attack_category==='R2L'?'#ff9500':alert.attack_category==='U2R'?'#e3b341':'#3fb950';
            return (
              <div key={i} className="block-card" style={{borderLeft:`3px solid ${borderColor}`}}>
                <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',cursor:'pointer'}}
                  onClick={() => setExpanded(expanded===i?null:i)}>
                  <div style={{display:'flex',alignItems:'center',gap:12}}>
                    <div style={{background:'rgba(88,166,255,0.1)',borderRadius:8,padding:'6px 12px',fontFamily:'monospace',fontSize:13,color:'#58a6ff',fontWeight:700}}>
                      Alert #{alert.alert_id}
                    </div>
                    <div>
                      <p style={{fontWeight:600,fontSize:13}}>{alert.attack_category} — {alert.source_ip} → {alert.destination_ip}</p>
                      <p style={{fontSize:11,color:'var(--text-muted)'}}>{new Date(alert.timestamp*1000).toLocaleString()} · Confidence: {alert.confidence}%</p>
                    </div>
                  </div>
                  <div style={{display:'flex',alignItems:'center',gap:10}}>
                    <span className={`badge badge-${alert.severity}`}>{alert.severity}</span>
                    <span style={{fontSize:12,color:'var(--text-muted)'}}>{expanded===i?'▲':'▼'}</span>
                  </div>
                </div>
                {expanded===i && (
                  <div style={{marginTop:14,borderTop:'1px solid var(--border)',paddingTop:14}}>
                    <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
                      <div>
                        {[['Attack',alert.attack_category],['Severity',alert.severity],['Source IP',alert.source_ip],['Dest IP',alert.destination_ip],['Confidence',`${alert.confidence}%`]].map(([l,v])=>(
                          <div key={l} style={{display:'flex',justifyContent:'space-between',padding:'4px 0',borderBottom:'1px solid rgba(48,54,61,0.4)'}}>
                            <span style={{fontSize:12,color:'var(--text-muted)'}}>{l}</span>
                            <span style={{fontSize:12,fontWeight:600}}>{v}</span>
                          </div>
                        ))}
                      </div>
                      <div>
                        <p style={{fontSize:11,color:'var(--text-muted)',marginBottom:6}}>TOP SHAP FEATURES</p>
                        {(() => { try { return JSON.parse(alert.top_features||'[]').map((f,j)=>(<div key={j} style={{fontSize:12,color:'#58a6ff',marginBottom:4,fontFamily:'monospace'}}>{f.feature}: <span style={{color:'#3fb950'}}>{f.value}</span></div>)); } catch { return <p style={{color:'var(--text-muted)',fontSize:12}}>{alert.top_features}</p>; }})()}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
          {alerts.length===0 && <div style={{textAlign:'center',padding:40,color:'var(--text-muted)'}}>No alerts on-chain yet. Run a simulation to log one.</div>}
        </div>
      )}

      {/* Transactions Tab */}
      {activeTab === 'transactions' && (
        <div className="card">
          <div className="table-wrap">
            <table>
              <thead><tr><th>Tx Hash</th><th>Block</th><th>From</th><th>Gas Used</th><th>Status</th><th>Time</th></tr></thead>
              <tbody>
                {[...txs].reverse().map((tx,i)=>(
                  <tr key={i}>
                    <td style={{fontFamily:'monospace',fontSize:11,color:'#58a6ff'}}>{tx.tx_hash?.slice(0,18)}...</td>
                    <td style={{fontFamily:'monospace',fontSize:12}}>#{tx.block_number}</td>
                    <td style={{fontFamily:'monospace',fontSize:11,color:'var(--text-muted)'}}>{tx.from?.slice(0,14)}...</td>
                    <td style={{fontSize:12}}>{tx.gas_used?.toLocaleString()}</td>
                    <td><span style={{fontSize:11,fontWeight:600,color:tx.status===1?'#3fb950':'#f85149'}}>{tx.status===1?'✅ Success':'❌ Failed'}</span></td>
                    <td style={{fontSize:11,color:'var(--text-muted)'}}>{new Date(tx.timestamp*1000).toLocaleTimeString()}</td>
                  </tr>
                ))}
                {txs.length===0 && <tr><td colSpan={6} style={{textAlign:'center',color:'var(--text-muted)',padding:24}}>No transactions yet.</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}