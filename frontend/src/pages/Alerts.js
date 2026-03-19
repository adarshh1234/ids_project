import React, { useEffect, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { fetchAlerts, updateStatus } from '../services/api';
import { Filter, RefreshCw } from 'lucide-react';

export default function Alerts() {
  const [alerts, setAlerts]     = useState([]);
  const [total, setTotal]       = useState(0);
  const [loading, setLoading]   = useState(true);
  const [filters, setFilters]   = useState({ severity:'', category:'', status:'' });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = {};
      if (filters.severity) params.severity = filters.severity;
      if (filters.category) params.category = filters.category;
      if (filters.status)   params.status   = filters.status;
      const { data } = await fetchAlerts(params);
      setAlerts(data.alerts);
      setTotal(data.count);
    } finally { setLoading(false); }
  }, [filters]);

  useEffect(() => { load(); }, [load]);

  const handleStatus = async (id, s) => {
    await updateStatus(id, s);
    load();
  };

  const SEV_COLOR = { critical:'#f85149', high:'#ff9500', warning:'#e3b341', info:'#3fb950' };

  return (
    <div className="page">
      <div className="page-header" style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start'}}>
        <div>
          <h1 className="page-title">Alerts</h1>
          <p className="page-sub">{total} total alerts</p>
        </div>
        <button className="btn btn-outline" onClick={load}><RefreshCw size={14}/> Refresh</button>
      </div>

      {/* Filters */}
      <div className="card" style={{marginBottom:20}}>
        <div style={{display:'flex',gap:16,alignItems:'center',flexWrap:'wrap'}}>
          <Filter size={14} color="var(--text-muted)"/>
          <Select label="Severity" value={filters.severity}
            onChange={v => setFilters(f => ({...f, severity:v}))}
            options={['','critical','high','warning','info']}/>
          <Select label="Category" value={filters.category}
            onChange={v => setFilters(f => ({...f, category:v}))}
            options={['','Normal','DoS','Probe','R2L','U2R']}/>
          <Select label="Status" value={filters.status}
            onChange={v => setFilters(f => ({...f, status:v}))}
            options={['','new','acknowledged','resolved']}/>
          <button className="btn btn-outline" style={{fontSize:12}}
            onClick={() => setFilters({severity:'',category:'',status:''})}>
            Clear
          </button>
        </div>
      </div>

      <div className="card">
        {loading ? (
          <div className="loading"><div className="spinner"/><span>Loading…</span></div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th><th>Timestamp</th><th>Source IP</th><th>Dest IP</th>
                  <th>Category</th><th>Confidence</th><th>Severity</th>
                  <th>Blockchain</th><th>Status</th><th>Action</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map(a => (
                  <tr key={a.id}>
                    <td>
                      <Link to={`/alerts/${a.id}`}
                        style={{color:'var(--accent)',textDecoration:'none',fontWeight:600}}>
                        #{a.id}
                      </Link>
                    </td>
                    <td style={{color:'var(--text-muted)',fontSize:12}}>
                      {new Date(a.timestamp).toLocaleString()}
                    </td>
                    <td style={{fontFamily:'monospace',fontSize:12}}>{a.source_ip}</td>
                    <td style={{fontFamily:'monospace',fontSize:12}}>{a.destination_ip}</td>
                    <td>
                      <span className={`badge badge-${a.severity}`}>{a.attack_category}</span>
                    </td>
                    <td>
                      <span style={{fontWeight:600,color:SEV_COLOR[a.severity]}}>{a.confidence}%</span>
                    </td>
                    <td><span className={`badge badge-${a.severity}`}>{a.severity}</span></td>
                    <td style={{fontSize:11,fontFamily:'monospace',color:'var(--accent)'}}>
                      {a.blockchain_block_index !== null ? `#${a.blockchain_block_index}` : '—'}
                    </td>
                    <td>
                      <StatusDot s={a.status}/>
                    </td>
                    <td>
                      <div style={{display:'flex',gap:6}}>
                        {a.status === 'new' && (
                          <button className="btn btn-outline" style={{padding:'4px 8px',fontSize:11}}
                            onClick={() => handleStatus(a.id, 'acknowledged')}>
                            ACK
                          </button>
                        )}
                        {a.status !== 'resolved' && (
                          <button className="btn btn-success" style={{padding:'4px 8px',fontSize:11}}
                            onClick={() => handleStatus(a.id, 'resolved')}>
                            Resolve
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
                {!alerts.length && (
                  <tr><td colSpan={10} style={{textAlign:'center',color:'var(--text-muted)',padding:32}}>
                    No alerts match filters.
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function Select({ label, value, onChange, options }) {
  return (
    <div style={{display:'flex',alignItems:'center',gap:6}}>
      <span style={{fontSize:12,color:'var(--text-muted)'}}>{label}:</span>
      <select className="form-select" style={{padding:'5px 10px'}}
        value={value} onChange={e => onChange(e.target.value)}>
        {options.map(o => <option key={o} value={o}>{o || 'All'}</option>)}
      </select>
    </div>
  );
}

function StatusDot({ s }) {
  const c = { new:'#58a6ff', acknowledged:'#e3b341', resolved:'#3fb950' };
  return (
    <span style={{display:'flex',alignItems:'center',gap:5,fontSize:12,color:c[s]}}>
      <span style={{width:6,height:6,borderRadius:'50%',background:c[s],flexShrink:0}}/>
      {s}
    </span>
  );
}
