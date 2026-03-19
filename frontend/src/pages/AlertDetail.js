import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { fetchAlert, updateStatus } from '../services/api';
import { ArrowLeft, ShieldAlert, Link2, Brain, CheckCircle } from 'lucide-react';

const SEV_COLOR = { critical:'#f85149', high:'#ff9500', warning:'#e3b341', info:'#3fb950' };
const CAT_COLOR = { Normal:'#3fb950', DoS:'#f85149', Probe:'#bc8cff', R2L:'#ff9500', U2R:'#e3b341' };

export default function AlertDetail() {
  const { id } = useParams();
  const [alert, setAlert] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    try {
      const { data } = await fetchAlert(id);
      setAlert(data);
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, [id]);

  const handleStatus = async (s) => {
    await updateStatus(id, s);
    load();
  };

  if (loading) return <div className="loading"><div className="spinner"/><span>Loading alert…</span></div>;
  if (!alert)  return <div className="page"><div className="error-box">Alert not found.</div></div>;

  const topFeats = alert.top_features || [];
  const maxShap  = Math.max(...topFeats.map(f => Math.abs(f.shap_value)), 0.001);
  const probs    = alert.probabilities || {};

  return (
    <div className="page">
      {/* Header */}
      <div style={{display:'flex',alignItems:'center',gap:12,marginBottom:24}}>
        <Link to="/alerts" className="btn btn-outline" style={{padding:'6px 12px'}}>
          <ArrowLeft size={14}/> Back
        </Link>
        <div>
          <h1 className="page-title">Alert #{alert.id}</h1>
          <p className="page-sub">{new Date(alert.timestamp).toLocaleString()}</p>
        </div>
        <div style={{marginLeft:'auto',display:'flex',gap:10}}>
          {alert.status !== 'acknowledged' && alert.status !== 'resolved' && (
            <button className="btn btn-outline" onClick={() => handleStatus('acknowledged')}>
              Acknowledge
            </button>
          )}
          {alert.status !== 'resolved' && (
            <button className="btn btn-success" onClick={() => handleStatus('resolved')}>
              <CheckCircle size={14}/> Resolve
            </button>
          )}
        </div>
      </div>

      {/* Summary Row */}
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr 1fr',gap:16,marginBottom:24}}>
        {/* Detection result */}
        <div className="card" style={{borderLeft:`4px solid ${SEV_COLOR[alert.severity] || '#58a6ff'}`}}>
          <p className="card-title"><ShieldAlert size={12} style={{marginRight:5}}/>Detection Result</p>
          <p style={{fontSize:26,fontWeight:800,color:CAT_COLOR[alert.attack_category]||'#58a6ff'}}>
            {alert.attack_category}
          </p>
          <p style={{fontSize:13,color:'var(--text-muted)',marginTop:4}}>{alert.description}</p>
          <div style={{marginTop:12,display:'flex',gap:10,flexWrap:'wrap'}}>
            <span className={`badge badge-${alert.severity}`}>{alert.severity}</span>
            <span style={{fontSize:13,color:'var(--text-muted)'}}>
              Confidence: <strong style={{color:'var(--text-primary)'}}>{alert.confidence}%</strong>
            </span>
          </div>
        </div>

        {/* Network info */}
        <div className="card">
          <p className="card-title">Network Info</p>
          <InfoRow label="Source IP"   value={alert.source_ip} mono/>
          <InfoRow label="Dest IP"     value={alert.destination_ip} mono/>
          <InfoRow label="Protocol"    value={alert.protocol}/>
          <InfoRow label="Status"      value={alert.status}/>
        </div>

        {/* Blockchain */}
        <div className="card">
          <p className="card-title"><Link2 size={12} style={{marginRight:5}}/>Blockchain Log</p>
          {alert.blockchain_block_index !== null ? (
            <>
              <InfoRow label="Block #"  value={alert.blockchain_block_index}/>
              <div style={{marginTop:8}}>
                <p style={{fontSize:11,color:'var(--text-muted)',marginBottom:4}}>Block Hash</p>
                <p style={{fontFamily:'monospace',fontSize:11,color:'var(--accent)',wordBreak:'break-all'}}>
                  {alert.blockchain_hash}
                </p>
              </div>
              <div style={{marginTop:12}}>
                <span style={{
                  fontSize:12,color:'#3fb950',
                  background:'rgba(63,185,80,0.1)',
                  border:'1px solid rgba(63,185,80,0.3)',
                  borderRadius:6,padding:'4px 10px'
                }}>
                  ✓ Immutably Logged
                </span>
              </div>
            </>
          ) : (
            <p style={{color:'var(--text-muted)',fontSize:13}}>Not yet logged to blockchain.</p>
          )}
        </div>
      </div>

      {/* SHAP + Probabilities */}
      <div style={{display:'grid',gridTemplateColumns:'2fr 1fr',gap:20,marginBottom:24}}>
        {/* SHAP */}
        <div className="card">
          <p className="card-title"><Brain size={12} style={{marginRight:5}}/>XAI — SHAP Feature Importance</p>
          <p style={{fontSize:12,color:'var(--text-muted)',marginBottom:16}}>
            Top features that influenced this prediction. 
            <span style={{color:'#3fb950'}}> Green</span> = pushed toward <em>{alert.attack_category}</em>.
            <span style={{color:'#f85149'}}> Red</span> = pushed against.
          </p>
          <div className="shap-bar-wrap">
            {topFeats.map((f, i) => {
              const pct = Math.abs(f.shap_value) / maxShap * 100;
              const color = f.impact === 'positive' ? '#3fb950' : '#f85149';
              return (
                <div className="shap-row" key={i}>
                  <span className="shap-label">{f.feature}</span>
                  <div className="shap-bar-bg">
                    <div className="shap-bar" style={{width:`${pct}%`, background:color}}/>
                  </div>
                  <span className="shap-val" style={{color}}>{f.shap_value.toFixed(4)}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Probabilities */}
        <div className="card">
          <p className="card-title">Class Probabilities</p>
          <div className="prob-list">
            {Object.entries(probs).sort((a,b) => b[1]-a[1]).map(([cls, pct]) => (
              <div className="prob-row" key={cls}>
                <span className="prob-name">{cls}</span>
                <div className="prob-bar-bg">
                  <div className="prob-bar" style={{
                    width:`${pct}%`,
                    background: CAT_COLOR[cls] || '#58a6ff'
                  }}/>
                </div>
                <span className="prob-pct" style={{color: CAT_COLOR[cls]||'#58a6ff'}}>{pct}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Raw Features */}
      <div className="card">
        <p className="card-title">Raw Network Features</p>
        <div style={{
          display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(200px,1fr))',
          gap:'8px 16px', marginTop:8
        }}>
          {Object.entries(alert.raw_features || {}).map(([k, v]) => (
            <div key={k} style={{display:'flex',justifyContent:'space-between',
              padding:'6px 0',borderBottom:'1px solid rgba(48,54,61,0.5)'}}>
              <span style={{fontSize:12,color:'var(--text-muted)'}}>{k}</span>
              <span style={{fontSize:12,fontWeight:600,fontFamily:'monospace'}}>{v}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function InfoRow({ label, value, mono }) {
  return (
    <div style={{display:'flex',justifyContent:'space-between',padding:'5px 0',
      borderBottom:'1px solid rgba(48,54,61,0.4)'}}>
      <span style={{fontSize:12,color:'var(--text-muted)'}}>{label}</span>
      <span style={{
        fontSize:12, fontWeight:600,
        fontFamily: mono ? 'monospace' : 'inherit',
        color:'var(--text-primary)'
      }}>{value}</span>
    </div>
  );
}
