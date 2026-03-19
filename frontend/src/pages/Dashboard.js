import React, { useEffect, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend
} from 'recharts';
import { fetchStats, simulate } from '../services/api';
import {
  ShieldAlert, ShieldCheck, Activity, Link2,
  RefreshCw, Zap
} from 'lucide-react';

const SEV_COLOR  = { critical:'#f85149', high:'#ff9500', warning:'#e3b341', info:'#3fb950' };
const CAT_COLOR  = { Normal:'#3fb950', DoS:'#f85149', Probe:'#bc8cff', R2L:'#ff9500', U2R:'#e3b341' };

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
  const [stats, setStats]       = useState(null);
  const [loading, setLoading]   = useState(true);
  const [simLoading, setSim]    = useState(false);
  const [lastSim, setLastSim]   = useState(null);

  const load = useCallback(async () => {
    try {
      const { data } = await fetchStats();
      setStats(data);
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, [load]);

  const handleSimulate = async () => {
    setSim(true);
    try {
      const { data } = await simulate();
      setLastSim(data);
      await load();
    } finally { setSim(false); }
  };

  if (loading) return <div className="loading"><div className="spinner"/><span>Loading dashboard…</span></div>;

  const catData  = stats ? Object.entries(stats.by_category).map(([k,v]) => ({ name:k, value:v })) : [];
  const sevData  = stats ? Object.entries(stats.by_severity).map(([k,v]) => ({ name:k, value:v })) : [];

  return (
    <div className="page">
      <div className="page-header" style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start'}}>
        <div>
          <h1 className="page-title">Security Dashboard</h1>
          <p className="page-sub">Real-time network intrusion monitoring · Auto-refreshes every 15s</p>
        </div>
        <div style={{display:'flex',gap:10}}>
          <button className="btn btn-outline" onClick={load}>
            <RefreshCw size={14}/> Refresh
          </button>
          <button className="btn btn-primary" onClick={handleSimulate} disabled={simLoading}>
            <Zap size={14}/> {simLoading ? 'Simulating…' : 'Simulate Traffic'}
          </button>
        </div>
      </div>

      {/* Simulation result banner */}
      {lastSim && (
        <div style={{
          background: lastSim.severity === 'info' ? 'rgba(63,185,80,0.1)' : 'rgba(248,81,73,0.1)',
          border: `1px solid ${lastSim.severity === 'info' ? 'rgba(63,185,80,0.3)' : 'rgba(248,81,73,0.3)'}`,
          borderRadius:10, padding:'14px 18px', marginBottom:22,
          display:'flex', alignItems:'center', justifyContent:'space-between'
        }}>
          <div>
            <span style={{fontWeight:700,fontSize:14}}>
              {lastSim.severity === 'info' ? '✅' : '🚨'} Detection: <span style={{color: SEV_COLOR[lastSim.severity]}}>{lastSim.prediction}</span>
            </span>
            <span style={{color:'#8b949e',fontSize:13,marginLeft:14}}>
              Confidence: {lastSim.confidence}% · Block #{lastSim.blockchain?.block_index}
            </span>
          </div>
          <Link to={`/alerts/${lastSim.alert_id}`} className="btn btn-outline" style={{fontSize:12}}>
            View Alert →
          </Link>
        </div>
      )}

      {/* Stat Cards */}
      <div className="stat-grid">
        <StatCard icon={<ShieldAlert size={20} color="#f85149"/>} label="Total Alerts" value={stats?.total_alerts ?? 0} sub="All time" />
        <StatCard icon={<Activity size={20} color="#ff9500"/>}    label="Unresolved"  value={stats?.unresolved ?? 0}    sub="Needs attention" />
        <StatCard icon={<Link2 size={20} color="#58a6ff"/>}       label="Chain Blocks" value={stats?.blockchain_blocks ?? 0} sub={stats?.chain_valid ? '✓ Verified' : '⚠ Tampered!'} />
        <StatCard icon={<ShieldCheck size={20} color="#3fb950"/>} label="DoS Detected" value={stats?.by_category?.DoS ?? 0} sub="Denial of Service" />
        <StatCard icon={<ShieldAlert size={20} color="#bc8cff"/>} label="Probe Detected" value={stats?.by_category?.Probe ?? 0} sub="Network scans" />
        <StatCard icon={<ShieldAlert size={20} color="#e3b341"/>} label="R2L / U2R"   value={(stats?.by_category?.R2L ?? 0) + (stats?.by_category?.U2R ?? 0)} sub="Privilege attacks" />
      </div>

      {/* Charts Row */}
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:20,marginBottom:28}}>
        {/* Category Bar */}
        <div className="card">
          <p className="card-title">Alerts by Category</p>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={catData} barSize={36}>
              <XAxis dataKey="name" tick={{fill:'#8b949e',fontSize:12}} axisLine={false} tickLine={false}/>
              <YAxis tick={{fill:'#8b949e',fontSize:11}} axisLine={false} tickLine={false}/>
              <Tooltip content={<CustomTooltip/>}/>
              <Bar dataKey="value" radius={[6,6,0,0]}>
                {catData.map((entry) => (
                  <Cell key={entry.name} fill={CAT_COLOR[entry.name] || '#58a6ff'}/>
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Pie */}
        <div className="card">
          <p className="card-title">Alerts by Severity</p>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={sevData} cx="50%" cy="50%" innerRadius={55} outerRadius={85}
                   dataKey="value" nameKey="name" paddingAngle={3}>
                {sevData.map((entry) => (
                  <Cell key={entry.name} fill={SEV_COLOR[entry.name] || '#58a6ff'}/>
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip/>}/>
              <Legend iconType="circle" iconSize={10}
                formatter={(v) => <span style={{color:'#8b949e',fontSize:12}}>{v}</span>}/>
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent Alerts */}
      <div className="card">
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:14}}>
          <p className="card-title" style={{margin:0}}>Recent Alerts</p>
          <Link to="/alerts" style={{fontSize:13,color:'var(--accent)',textDecoration:'none'}}>
            View all →
          </Link>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th><th>Time</th><th>Source IP</th>
                <th>Category</th><th>Confidence</th><th>Severity</th><th>Status</th>
              </tr>
            </thead>
            <tbody>
              {(stats?.recent_alerts || []).map(a => (
                <tr key={a.id}>
                  <td><Link to={`/alerts/${a.id}`} style={{color:'var(--accent)',textDecoration:'none'}}>#{a.id}</Link></td>
                  <td style={{color:'var(--text-muted)'}}>{new Date(a.timestamp).toLocaleTimeString()}</td>
                  <td style={{fontFamily:'monospace',fontSize:12}}>{a.source_ip}</td>
                  <td><span className={`badge badge-${a.severity}`}>{a.attack_category}</span></td>
                  <td>{a.confidence}%</td>
                  <td><SevBadge s={a.severity}/></td>
                  <td><StatusBadge s={a.status}/></td>
                </tr>
              ))}
              {!(stats?.recent_alerts?.length) && (
                <tr><td colSpan={7} style={{textAlign:'center',color:'var(--text-muted)',padding:24}}>
                  No alerts yet. Click "Simulate Traffic" to test.
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
      <p className="stat-value">{value.toLocaleString()}</p>
      <p className="stat-sub">{sub}</p>
    </div>
  );
}

function SevBadge({ s }) {
  return <span className={`badge badge-${s}`}>{s}</span>;
}
function StatusBadge({ s }) {
  const colors = { new:'#58a6ff', acknowledged:'#e3b341', resolved:'#3fb950' };
  return <span style={{fontSize:11,color:colors[s],fontWeight:600}}>{s}</span>;
}
