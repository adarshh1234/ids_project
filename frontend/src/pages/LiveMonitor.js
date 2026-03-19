import React, { useEffect, useState, useRef, useCallback } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';
import { Activity, Wifi, WifiOff, AlertTriangle, CheckCircle, Zap } from 'lucide-react';

const API = axios.create({ baseURL: '/api' });
const SEV_COLOR = { critical:'#f85149', high:'#ff9500', warning:'#e3b341', info:'#3fb950' };
const CAT_COLOR = { Normal:'#3fb950', DoS:'#f85149', Probe:'#bc8cff', R2L:'#ff9500', U2R:'#e3b341' };

export default function LiveMonitor() {
  const [alerts, setAlerts]       = useState([]);
  const [status, setStatus]       = useState(null);
  const [connected, setConnected] = useState(false);
  const [pulse, setPulse]         = useState(false);
  const prevCount = useRef(0);
  const intervalRef = useRef(null);

  const fetchLive = useCallback(async () => {
    try {
      const [s, a] = await Promise.all([
        API.get('/capture/status/'),
        API.get('/capture/recent/?n=30'),
      ]);
      setStatus(s.data);
      setConnected(true);

      const newAlerts = a.data;
      // Flash pulse if new alerts arrived
      if (newAlerts.length > prevCount.current) {
        setPulse(true);
        setTimeout(() => setPulse(false), 600);
      }
      prevCount.current = newAlerts.length;
      setAlerts(newAlerts);
    } catch {
      setConnected(false);
    }
  }, []);

  useEffect(() => {
    fetchLive();
    intervalRef.current = setInterval(fetchLive, 3000); // poll every 3s
    return () => clearInterval(intervalRef.current);
  }, [fetchLive]);

  return (
    <div className="page">
      {/* Header */}
      <div className="page-header" style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start'}}>
        <div>
          <h1 className="page-title" style={{display:'flex',alignItems:'center',gap:10}}>
            <span style={{
              width:10, height:10, borderRadius:'50%',
              background: connected ? '#3fb950' : '#f85149',
              boxShadow: connected ? '0 0 8px #3fb950' : 'none',
              display:'inline-block',
              animation: connected ? 'pulse-dot 1.5s infinite' : 'none',
            }}/>
            Live Monitor
          </h1>
          <p className="page-sub">
            Real-time network traffic analysis · Auto-refreshes every 3s
          </p>
        </div>
        <div style={{display:'flex',alignItems:'center',gap:8,
          padding:'8px 14px', borderRadius:8,
          background: connected ? 'rgba(63,185,80,0.1)' : 'rgba(248,81,73,0.1)',
          border: `1px solid ${connected ? 'rgba(63,185,80,0.3)' : 'rgba(248,81,73,0.3)'}`,
        }}>
          {connected ? <Wifi size={14} color="#3fb950"/> : <WifiOff size={14} color="#f85149"/>}
          <span style={{fontSize:13,fontWeight:600,color:connected?'#3fb950':'#f85149'}}>
            {connected ? 'Backend Connected' : 'Backend Offline'}
          </span>
        </div>
      </div>

      {/* Capture setup instructions banner */}
      <div style={{
        background:'rgba(88,166,255,0.07)',
        border:'1px solid rgba(88,166,255,0.2)',
        borderRadius:10, padding:'14px 18px', marginBottom:24,
        display:'flex', alignItems:'flex-start', gap:12,
      }}>
        <Zap size={16} color="#58a6ff" style={{marginTop:2,flexShrink:0}}/>
        <div>
          <p style={{fontWeight:600,fontSize:13,color:'#58a6ff',marginBottom:4}}>
            Start the capture agent to see real traffic here
          </p>
          <p style={{fontSize:12,color:'var(--text-muted)',fontFamily:'monospace'}}>
            cd ids_project/network_capture<br/>
            pip install scapy requests<br/>
            sudo python capture.py --iface eth0 --api http://localhost:8000
          </p>
          <p style={{fontSize:11,color:'var(--text-muted)',marginTop:6}}>
            Replace <code style={{color:'#e3b341'}}>eth0</code> with your interface
            (run <code style={{color:'#e3b341'}}>python capture.py --list</code> to see options).
            Requires root/admin privileges for raw packet access.
          </p>
        </div>
      </div>

      {/* Status cards */}
      {status && (
        <div className="stat-grid" style={{marginBottom:24}}>
          <MiniStat label="Alerts / min"    value={status.rate_per_min}    color="#58a6ff"/>
          <MiniStat label="Last 1 min"      value={status.alerts_last_1min} color="#3fb950"/>
          <MiniStat label="Last 5 min"      value={status.alerts_last_5min} color="#e3b341"/>
          <MiniStat label="Attacks (5 min)" value={status.attacks_last_5min} color="#f85149"/>
          <div className="stat-card">
            <p className="stat-label">Last Detection</p>
            <p style={{fontSize:13,fontWeight:700,
              color: CAT_COLOR[status.last_alert_type] || 'var(--text-muted)',
              marginTop:4}}>
              {status.last_alert_type || '—'}
            </p>
            <p className="stat-sub">
              {status.last_alert_time
                ? new Date(status.last_alert_time).toLocaleTimeString()
                : 'No alerts yet'}
            </p>
          </div>
        </div>
      )}

      {/* Live feed table */}
      <div className="card" style={{
        borderColor: pulse ? 'rgba(88,166,255,0.6)' : 'var(--border)',
        transition: 'border-color 0.3s',
      }}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:14}}>
          <p className="card-title" style={{margin:0,display:'flex',alignItems:'center',gap:8}}>
            <Activity size={13}/>
            Live Alert Feed
            <span style={{
              fontSize:11, fontWeight:700,
              background:'rgba(88,166,255,0.15)',
              color:'#58a6ff', borderRadius:10,
              padding:'2px 8px',
            }}>{alerts.length}</span>
          </p>
          <span style={{fontSize:11,color:'var(--text-muted)'}}>Newest first</span>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Source IP</th>
                <th>Dest IP</th>
                <th>Protocol</th>
                <th>Category</th>
                <th>Confidence</th>
                <th>Severity</th>
                <th>Chain</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((a, i) => (
                <tr key={a.id} style={{
                  animation: i === 0 && pulse ? 'flash-row 0.6s ease' : 'none',
                }}>
                  <td style={{fontSize:11,color:'var(--text-muted)',fontFamily:'monospace'}}>
                    {new Date(a.timestamp).toLocaleTimeString()}
                  </td>
                  <td style={{fontFamily:'monospace',fontSize:12}}>{a.source_ip}</td>
                  <td style={{fontFamily:'monospace',fontSize:12}}>{a.destination_ip}</td>
                  <td style={{fontSize:12,color:'var(--text-muted)',textTransform:'uppercase'}}>
                    {a.protocol}
                  </td>
                  <td>
                    <span className={`badge badge-${a.severity}`}>
                      {a.attack_category}
                    </span>
                  </td>
                  <td>
                    <span style={{
                      fontWeight:700, fontSize:13,
                      color: SEV_COLOR[a.severity] || 'var(--text-primary)',
                    }}>{a.confidence}%</span>
                  </td>
                  <td>
                    <div style={{display:'flex',alignItems:'center',gap:5}}>
                      {a.severity === 'info'
                        ? <CheckCircle size={13} color="#3fb950"/>
                        : <AlertTriangle size={13} color={SEV_COLOR[a.severity]}/>
                      }
                      <span style={{fontSize:12,color:SEV_COLOR[a.severity]}}>{a.severity}</span>
                    </div>
                  </td>
                  <td style={{fontFamily:'monospace',fontSize:11,color:'#58a6ff'}}>
                    {a.blockchain_block_index !== null ? `#${a.blockchain_block_index}` : '—'}
                  </td>
                  <td>
                    <Link to={`/alerts/${a.id}`}
                      style={{color:'var(--accent)',fontSize:12,textDecoration:'none',fontWeight:600}}>
                      View →
                    </Link>
                  </td>
                </tr>
              ))}
              {alerts.length === 0 && (
                <tr>
                  <td colSpan={9} style={{textAlign:'center',padding:40,color:'var(--text-muted)'}}>
                    <div style={{display:'flex',flexDirection:'column',alignItems:'center',gap:10}}>
                      <Activity size={32} strokeWidth={1} color="var(--text-muted)"/>
                      <p>No live traffic yet.</p>
                      <p style={{fontSize:12}}>
                        Start the capture agent or use{' '}
                        <Link to="/" style={{color:'var(--accent)'}}>Simulate Traffic</Link>
                        {' '}on the dashboard.
                      </p>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* CSS keyframes injected inline */}
      <style>{`
        @keyframes pulse-dot {
          0%, 100% { opacity: 1; transform: scale(1); }
          50%       { opacity: 0.5; transform: scale(1.3); }
        }
        @keyframes flash-row {
          0%   { background: rgba(88,166,255,0.15); }
          100% { background: transparent; }
        }
      `}</style>
    </div>
  );
}

function MiniStat({ label, value, color }) {
  return (
    <div className="stat-card">
      <p className="stat-label">{label}</p>
      <p className="stat-value" style={{color}}>{value ?? '—'}</p>
    </div>
  );
}
