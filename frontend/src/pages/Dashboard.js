import React, { useEffect, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts';
import { fetchStats, simulate } from '../services/api';
import { ShieldAlert, ShieldCheck, Activity, Link2, RefreshCw, Zap } from 'lucide-react';

const SEV_COLOR = { critical:'#f85149', high:'#ff9500', warning:'#e3b341', info:'#3fb950' };
const CAT_COLOR = { Normal:'#3fb950', DoS:'#f85149', Probe:'#bc8cff', R2L:'#ff9500', U2R:'#e3b341' };

const ATTACK_BUTTONS = [
  { type:'random', label:'🎲 Random',   color:'#58a6ff' },
  { type:'normal', label:'✅ Normal',   color:'#3fb950' },
  { type:'dos',    label:'🔴 DoS',      color:'#f85149' },
  { type:'probe',  label:'🟣 Probe',    color:'#bc8cff' },
  { type:'r2l',    label:'🟠 R2L',      color:'#ff9500' },
  { type:'u2r',    label:'🟡 U2R',      color:'#e3b341' },
];

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{background:'#1c2128',border:'1px solid #30363d',borderRadius:8,padding:'10px 14px'}}>
      <p style={{color:'#e6edf3',fontSize:13,fontWeight:600}}>{label}</p>
      {payload.map(p => (
        <p key={p.name} style={{color:p.fill||p.color,fontSize:12,marginTop:4}}>
          {p.name}: <strong>{p.value}</strong>
        </p>
      ))}
    </div>
  );
};

export default function Dashboard() {
  const [stats, setStats]     = useState(null);
  const [loading, setLoading] = useState(true);
  const [simLoading, setSim]  = useState(null);
  const [lastSim, setLastSim] = useState(null);

  const load = useCallback(async () => {
    try { const { data } = await fetchStats(); setStats(data); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, [load]);

  const handleSimulate = async (type) => {
    setSim(type);
    try {
      const { data } = await simulate(type === 'random' ? null : type);
      setLastSim(data);
      await load();
    } finally { setSim(null); }
  };

  if (loading) return <div className="loading"><div className="spinner"/><span>Loading dashboard…</span></div>;

  const catData = stats ? Object.entries(stats.by_category).map(([k,v]) => ({ name:k, value:v })) : [];
  const sevData = stats ? Object.entries(stats.by_severity).map(([k,v]) => ({ name:k, value:v })) : [];

  return (
    <div className="page">
      <div className="page-header" style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start'}}>
        <div>
          <h1 className="page-title">Security Dashboard</h1>
          <p className="page-sub"></p>
          {stats?.contract_address && (
            <p style={{fontSize:11,color:'#58a6ff',marginTop:4,fontFamily:'monospace'}}>
              ⛓️ Ganache: {stats.contract_address.slice(0,20)}...
            </p>
          )}
        </div>
        <button className="btn btn-outline" onClick={load}><RefreshCw size={14}/> Refresh</button>
      </div>

      {/* Simulate Attack Buttons */}
      <div className="card" style={{marginBottom:22}}>
        <p className="card-title" style={{marginBottom:12}}>
          <Zap size={12} style={{marginRight:5}}/>Simulate Attack
        </p>
        <div style={{display:'flex',gap:8,flexWrap:'wrap'}}>
          {ATTACK_BUTTONS.map(({type, label, color}) => (
            <button key={type} className="btn"
              disabled={simLoading !== null}
              onClick={() => handleSimulate(type)}
              style={{
                background:`${color}18`,
                color,
                border:`1px solid ${color}44`,
                fontSize:12,fontWeight:600,
              }}>
              {simLoading === type ? '⏳ Running...' : label}
            </button>
          ))}
        </div>
      </div>

      {/* Simulation Result Banner */}
      {lastSim && (
        <div style={{
          background: lastSim.severity==='info' ? 'rgba(63,185,80,0.1)':'rgba(248,81,73,0.1)',
          border:`1px solid ${lastSim.severity==='info' ? 'rgba(63,185,80,0.3)':'rgba(248,81,73,0.3)'}`,
          borderRadius:10, padding:'14px 18px', marginBottom:22,
          display:'flex', alignItems:'center', justifyContent:'space-between',
        }}>
          <div>
            <span style={{fontWeight:700,fontSize:14}}>
              {lastSim.severity==='info'?'✅':'🚨'} Detection:{' '}
              <span style={{color:CAT_COLOR[lastSim.prediction]}}>{lastSim.prediction}</span>
            </span>
            <span style={{color:'#8b949e',fontSize:13,marginLeft:14}}>
              Confidence: {lastSim.confidence}%
              {lastSim.blockchain?.tx_hash && (
                <span style={{marginLeft:8,fontFamily:'monospace',color:'#58a6ff'}}>
                  Tx: {lastSim.blockchain.tx_hash.slice(0,16)}...
                </span>
              )}
              {lastSim.blockchain?.gas_used && (
                <span style={{marginLeft:8,color:'#e3b341'}}>
                  Gas: {lastSim.blockchain.gas_used.toLocaleString()}
                </span>
              )}
            </span>
          </div>
          <Link to={`/alerts/${lastSim.alert_id}`} className="btn btn-outline" style={{fontSize:12}}>
            View Alert →
          </Link>
        </div>
      )}

      {/* Stat Cards */}
      <div className="stat-grid">
        <StatCard icon={<ShieldAlert size={20} color="#f85149"/>} label="Total Alerts"   value={stats?.total_alerts??0}          sub="All time"/>
        <StatCard icon={<Activity    size={20} color="#ff9500"/>} label="Unresolved"     value={stats?.unresolved??0}            sub="Needs attention"/>
        <StatCard icon={<Link2       size={20} color="#58a6ff"/>} label="Chain Blocks"   value={stats?.blockchain_blocks??0}     sub={stats?.chain_valid?'✓ Ganache Connected':'⚠ Disconnected'}/>
        <StatCard icon={<ShieldCheck size={20} color="#f85149"/>} label="DoS Detected"  value={stats?.by_category?.DoS??0}     sub="Denial of Service"/>
        <StatCard icon={<ShieldAlert size={20} color="#bc8cff"/>} label="Probe Detected" value={stats?.by_category?.Probe??0}   sub="Network scans"/>
        <StatCard icon={<ShieldAlert size={20} color="#ff9500"/>} label="R2L Detected"  value={stats?.by_category?.R2L??0}     sub="Remote to Local"/>
        <StatCard icon={<ShieldAlert size={20} color="#e3b341"/>} label="U2R Detected"  value={stats?.by_category?.U2R??0}     sub="Privilege escalation"/>
      </div>

      {/* Charts */}
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:20,marginBottom:28}}>
        <div className="card">
          <p className="card-title">Alerts by Category</p>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={catData} barSize={36}>
              <XAxis dataKey="name" tick={{fill:'#8b949e',fontSize:12}} axisLine={false} tickLine={false}/>
              <YAxis tick={{fill:'#8b949e',fontSize:11}} axisLine={false} tickLine={false}/>
              <Tooltip content={<CustomTooltip/>}/>
              <Bar dataKey="value" radius={[6,6,0,0]}>
                {catData.map(e => <Cell key={e.name} fill={CAT_COLOR[e.name]||'#58a6ff'}/>)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="card">
          <p className="card-title">Alerts by Severity</p>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={sevData} cx="50%" cy="50%" innerRadius={55} outerRadius={85}
                dataKey="value" nameKey="name" paddingAngle={3}>
                {sevData.map(e => <Cell key={e.name} fill={SEV_COLOR[e.name]||'#58a6ff'}/>)}
              </Pie>
              <Tooltip content={<CustomTooltip/>}/>
              <Legend iconType="circle" iconSize={10}
                formatter={v => <span style={{color:'#8b949e',fontSize:12}}>{v}</span>}/>
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent Alerts */}
      <div className="card">
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:14}}>
          <p className="card-title" style={{margin:0}}>Recent Alerts</p>
          <Link to="/alerts" style={{fontSize:13,color:'var(--accent)',textDecoration:'none'}}>View all →</Link>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>ID</th><th>Time</th><th>Source IP</th><th>Category</th><th>Confidence</th><th>Severity</th><th>Tx Hash</th><th>Status</th></tr>
            </thead>
            <tbody>
              {(stats?.recent_alerts||[]).map(a => (
                <tr key={a.id}>
                  <td><Link to={`/alerts/${a.id}`} style={{color:'var(--accent)',textDecoration:'none'}}>#{a.id}</Link></td>
                  <td style={{color:'var(--text-muted)'}}>{new Date(a.timestamp).toLocaleTimeString()}</td>
                  <td style={{fontFamily:'monospace',fontSize:12}}>{a.source_ip}</td>
                  <td><span className={`badge badge-${a.severity}`}>{a.attack_category}</span></td>
                  <td>{a.confidence}%</td>
                  <td><span className={`badge badge-${a.severity}`}>{a.severity}</span></td>
                  <td style={{fontFamily:'monospace',fontSize:11,color:'#58a6ff'}}>
                    {a.blockchain_hash ? a.blockchain_hash.slice(0,12)+'...' : '—'}
                  </td>
                  <td style={{fontSize:11,color:'var(--text-muted)'}}>{a.status}</td>
                </tr>
              ))}
              {!(stats?.recent_alerts?.length) && (
                <tr><td colSpan={8} style={{textAlign:'center',color:'var(--text-muted)',padding:24}}>
                  No alerts yet. Click an attack button above to test.
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function StatCard({ icon, label, value, sub }) {
  return (
    <div className="stat-card">
      <div className="stat-icon">{icon}</div>
      <p className="stat-label">{label}</p>
      <p className="stat-value">{typeof value==='number'?value.toLocaleString():value}</p>
      <p className="stat-sub">{sub}</p>
    </div>
  );
}
