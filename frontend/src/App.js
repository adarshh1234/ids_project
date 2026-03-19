import React, { useState } from 'react';
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom';
import Dashboard   from './pages/Dashboard';
import LiveMonitor from './pages/LiveMonitor';
import Alerts      from './pages/Alerts';
import AlertDetail from './pages/AlertDetail';
import Predict     from './pages/Predict';
import BlockchainPage from './pages/BlockchainPage';
import {
  LayoutDashboard, ShieldAlert, Brain, Link2, Menu, X, Shield, Activity
} from 'lucide-react';
import './App.css';

const NAV = [
  { to: '/',           label: 'Dashboard',    icon: LayoutDashboard },
  { to: '/live',       label: 'Live Monitor', icon: Activity },
  { to: '/alerts',     label: 'Alerts',       icon: ShieldAlert },
  { to: '/predict',    label: 'Predict',      icon: Brain },
  { to: '/blockchain', label: 'Blockchain',   icon: Link2 },
];

export default function App() {
  const [open, setOpen] = useState(true);

  return (
    <BrowserRouter>
      <div className="app-layout">
        {/* Sidebar */}
        <aside className={`sidebar ${open ? 'open' : 'collapsed'}`}>
          <div className="sidebar-header">
            <Shield size={22} className="logo-icon" />
            {open && <span className="logo-text">IDS<span className="logo-accent">Guard</span></span>}
            <button className="toggle-btn" onClick={() => setOpen(!open)}>
              {open ? <X size={16}/> : <Menu size={16}/>}
            </button>
          </div>

          <nav className="sidebar-nav">
            {NAV.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                end={to === '/'}
                className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
              >
                <Icon size={18} />
                {open && <span>{label}</span>}
              </NavLink>
            ))}
          </nav>

          {open && (
            <div className="sidebar-footer">
              <div className="footer-badge">
                <span className="dot green" />
                <span>System Online</span>
              </div>
              <p className="footer-sub">NSL-KDD · Random Forest · SHAP</p>
            </div>
          )}
        </aside>

        {/* Main */}
        <main className="main-content">
          <Routes>
            <Route path="/"            element={<Dashboard />} />
            <Route path="/live"        element={<LiveMonitor />} />
            <Route path="/alerts"      element={<Alerts />} />
            <Route path="/alerts/:id"  element={<AlertDetail />} />
            <Route path="/predict"     element={<Predict />} />
            <Route path="/blockchain"  element={<BlockchainPage />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
