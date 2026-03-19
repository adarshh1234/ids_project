import React, { useState } from 'react';
import { predict } from '../services/api';
import { Brain, Zap } from 'lucide-react';

const SEV_COLOR = { critical:'#f85149', high:'#ff9500', warning:'#e3b341', info:'#3fb950' };
const CAT_COLOR = { Normal:'#3fb950', DoS:'#f85149', Probe:'#bc8cff', R2L:'#ff9500', U2R:'#e3b341' };

const DEFAULTS = {
  duration:0, protocol_type:'tcp', service:'http', flag:'SF',
  src_bytes:232, dst_bytes:8153, land:0, wrong_fragment:0, urgent:0,
  hot:0, num_failed_logins:0, logged_in:1, num_compromised:0, root_shell:0,
  su_attempted:0, num_root:0, num_file_creations:0, num_shells:0,
  num_access_files:0, num_outbound_cmds:0, is_host_login:0, is_guest_login:0,
  count:5, srv_count:5, serror_rate:0, srv_serror_rate:0, rerror_rate:0,
  srv_rerror_rate:0, same_srv_rate:1.0, diff_srv_rate:0, srv_diff_host_rate:0,
  dst_host_count:255, dst_host_srv_count:255, dst_host_same_srv_rate:1.0,
  dst_host_diff_srv_rate:0, dst_host_same_src_port_rate:0,
  dst_host_srv_diff_host_rate:0, dst_host_serror_rate:0,
  dst_host_srv_serror_rate:0, dst_host_rerror_rate:0, dst_host_srv_rerror_rate:0,
  source_ip:'192.168.1.1', destination_ip:'10.0.0.1',
};

const PRESETS = {
  'Normal HTTP': DEFAULTS,
  'Neptune (DoS)': {
    ...DEFAULTS, protocol_type:'tcp', service:'private', flag:'S0',
    src_bytes:0, dst_bytes:0, logged_in:0, count:511, srv_count:511,
    serror_rate:1.0, srv_serror_rate:1.0, same_srv_rate:1.0,
    dst_host_count:255, dst_host_srv_count:255, dst_host_same_srv_rate:1.0,
    dst_host_serror_rate:1.0, dst_host_srv_serror_rate:1.0,
    source_ip:'10.0.0.5', destination_ip:'192.168.1.10',
  },
  'Portsweep (Probe)': {
    ...DEFAULTS, protocol_type:'tcp', service:'finger', flag:'S0',
    src_bytes:0, dst_bytes:0, logged_in:0, count:1, srv_count:1,
    serror_rate:1.0, srv_diff_host_rate:1.0, dst_host_count:255, dst_host_srv_count:4,
    dst_host_same_srv_rate:0.02, dst_host_rerror_rate:0.5, dst_host_srv_rerror_rate:1.0,
    source_ip:'10.10.10.2', destination_ip:'192.168.0.50',
  },
};

const FIELDS_BASIC = [
  {key:'source_ip',      label:'Source IP',          type:'text'},
  {key:'destination_ip', label:'Destination IP',      type:'text'},
  {key:'protocol_type',  label:'Protocol',            type:'select', opts:['tcp','udp','icmp']},
  {key:'service',        label:'Service',             type:'text'},
  {key:'flag',           label:'Flag',                type:'select', opts:['SF','S0','S1','REJ','RSTO','SH','OTH']},
  {key:'duration',       label:'Duration (s)',         type:'number'},
  {key:'src_bytes',      label:'Src Bytes',           type:'number'},
  {key:'dst_bytes',      label:'Dst Bytes',           type:'number'},
  {key:'logged_in',      label:'Logged In',           type:'select', opts:['0','1']},
  {key:'count',          label:'Count',               type:'number'},
  {key:'srv_count',      label:'Srv Count',           type:'number'},
  {key:'serror_rate',    label:'SYN Error Rate',      type:'number'},
  {key:'rerror_rate',    label:'REJ Error Rate',      type:'number'},
  {key:'same_srv_rate',  label:'Same Srv Rate',       type:'number'},
];

export default function Predict() {
  const [form, setForm]       = useState(DEFAULTS);
  const [result, setResult]   = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');

  const handleChange = (k, v) => setForm(f => ({...f, [k]: isNaN(v) || typeof v === 'string' && v.includes('.') ? v : Number(v)}));

  const handlePreset = (name) => setForm(PRESETS[name]);

  const handleSubmit = async () => {
    setLoading(true); setError(''); setResult(null);
    try {
      const { data } = await predict(form);
      setResult(data);
    } catch(e) {
      setError(e.response?.data?.error || 'Prediction failed. Ensure model is trained.');
    } finally { setLoading(false); }
  };

  const topFeats  = result?.top_features || [];
  const maxShap   = Math.max(...topFeats.map(f => Math.abs(f.shap_value)), 0.001);

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Manual Prediction</h1>
        <p className="page-sub">Enter network traffic features to get an instant AI-powered classification with SHAP explanation.</p>
      </div>

      {/* Presets */}
      <div style={{display:'flex',gap:10,marginBottom:20,flexWrap:'wrap'}}>
        <span style={{fontSize:13,color:'var(--text-muted)',alignSelf:'center'}}>
          <Zap size={13}/> Presets:
        </span>
        {Object.keys(PRESETS).map(p => (
          <button key={p} className="btn btn-outline" style={{fontSize:12}}
            onClick={() => handlePreset(p)}>{p}</button>
        ))}
      </div>

      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:24,alignItems:'start'}}>
        {/* Input form */}
        <div className="card">
          <p className="card-title">Network Traffic Features</p>
          <div className="form-grid" style={{marginBottom:18}}>
            {FIELDS_BASIC.map(({key, label, type, opts}) => (
              <div className="form-group" key={key}>
                <label className="form-label">{label}</label>
                {type === 'select' ? (
                  <select className="form-select" value={form[key]}
                    onChange={e => handleChange(key, e.target.value)}>
                    {opts.map(o => <option key={o} value={o}>{o}</option>)}
                  </select>
                ) : (
                  <input className="form-input" type={type === 'number' ? 'number' : 'text'}
                    value={form[key]} onChange={e => handleChange(key, e.target.value)}
                    step={type === 'number' ? 'any' : undefined}/>
                )}
              </div>
            ))}
          </div>

          {error && <div className="error-box" style={{marginBottom:14}}>{error}</div>}

          <button className="btn btn-primary" style={{width:'100%',justifyContent:'center'}}
            onClick={handleSubmit} disabled={loading}>
            <Brain size={15}/>
            {loading ? 'Analysing…' : 'Run Prediction + SHAP'}
          </button>
        </div>

        {/* Result */}
        {result ? (
          <div style={{display:'flex',flexDirection:'column',gap:16}}>
            {/* Verdict */}
            <div className="card" style={{borderLeft:`4px solid ${SEV_COLOR[result.severity]}`}}>
              <p className="card-title">Detection Result</p>
              <p style={{fontSize:32,fontWeight:800,color:CAT_COLOR[result.prediction]||'#58a6ff'}}>
                {result.prediction}
              </p>
              <p style={{fontSize:13,color:'var(--text-muted)',marginTop:4}}>{result.description}</p>
              <div style={{marginTop:12,display:'flex',gap:12,flexWrap:'wrap',alignItems:'center'}}>
                <span className={`badge badge-${result.severity}`}>{result.severity}</span>
                <span style={{fontSize:13,color:'var(--text-muted)'}}>
                  Confidence: <strong style={{color:'var(--text-primary)'}}>{result.confidence}%</strong>
                </span>
                <span style={{fontSize:12,color:'var(--accent)',fontFamily:'monospace'}}>
                  Block #{result.blockchain?.block_index}
                </span>
              </div>
            </div>

            {/* SHAP */}
            <div className="card">
              <p className="card-title"><Brain size={12} style={{marginRight:5}}/>Top SHAP Features</p>
              <p style={{fontSize:12,color:'var(--text-muted)',marginBottom:12}}>
                Why the model made this prediction:
              </p>
              <div className="shap-bar-wrap">
                {topFeats.map((f, i) => {
                  const pct   = Math.abs(f.shap_value) / maxShap * 100;
                  const color = f.impact === 'positive' ? '#3fb950' : '#f85149';
                  return (
                    <div className="shap-row" key={i}>
                      <span className="shap-label">{f.feature}</span>
                      <div className="shap-bar-bg">
                        <div className="shap-bar" style={{width:`${pct}%`,background:color}}/>
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
                {Object.entries(result.probabilities||{}).sort((a,b)=>b[1]-a[1]).map(([cls,pct]) => (
                  <div className="prob-row" key={cls}>
                    <span className="prob-name">{cls}</span>
                    <div className="prob-bar-bg">
                      <div className="prob-bar" style={{width:`${pct}%`,background:CAT_COLOR[cls]||'#58a6ff'}}/>
                    </div>
                    <span className="prob-pct" style={{color:CAT_COLOR[cls]||'#58a6ff'}}>{pct}%</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="card" style={{display:'flex',flexDirection:'column',
            alignItems:'center',justifyContent:'center',padding:60,gap:14,
            border:'2px dashed var(--border)'}}>
            <Brain size={40} color="var(--text-muted)" strokeWidth={1}/>
            <p style={{color:'var(--text-muted)',fontSize:14,textAlign:'center'}}>
              Fill in the network features and click<br/><strong>Run Prediction + SHAP</strong>
            </p>
            <p style={{color:'var(--text-muted)',fontSize:12,textAlign:'center'}}>
              Or use a preset above to auto-fill known attack patterns
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
