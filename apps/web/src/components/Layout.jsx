import { useEffect, useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import Icon from './icons';
import { useAuthStore } from '../store/authStore';
import { systemApi } from '../api';

const links = [
  { to: '/', label: 'Dashboard', end: true, icon: 'Dashboard' },
  { to: '/alerts', label: 'Alerts', icon: 'Alert' },
  { to: '/parse', label: 'Parse Log', roles: ['admin', 'analyst'], icon: 'Terminal' },
  { to: '/users', label: 'Users', roles: ['admin'], icon: 'Users' },
  { to: '/audit', label: 'Audit', roles: ['admin'], icon: 'Audit' },
];

const TITLES = {
  '/': 'Threat Overview',
  '/alerts': 'Alerts',
  '/parse': 'Parse Log',
  '/users': 'Users & Roles',
  '/audit': 'Audit Trail',
};


export default function Layout({ children }) {
  const { user, logout } = useAuthStore();
  const location = useLocation();
  const [status, setStatus] = useState(null);
  const [mobileOpen, setMobileOpen] = useState(false);

  // Lightweight health probe — refreshed on navigation (no polling).
  useEffect(() => {
    let cancelled = false;
    systemApi
      .health()
      .then((res) => !cancelled && setStatus(res.data))
      .catch(() => !cancelled && setStatus({ status: 'error' }));
    return () => {
      cancelled = true;
    };
  }, [location.pathname]);

  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname]);

  const visible = links.filter((l) => !l.roles || (user && l.roles.includes(user.role)));
  const modelOk = Boolean(status?.model?.startsWith('ok'));
  const overall = status?.status === 'ok' ? 'ok' : status ? 'error' : 'unknown';

  return (
    <div className="flex min-h-screen">
      <Sidebar
        items={visible}
        status={status}
        modelOk={modelOk}
        overall={overall}
        mobileOpen={mobileOpen}
        onClose={() => setMobileOpen(false)}
      />

      {mobileOpen && (
        <div
          className="fixed inset-0 z-20 bg-black/60 lg:hidden"
          onClick={() => setMobileOpen(false)}
          aria-hidden="true"
        />
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar
          title={TITLES[location.pathname] || 'ACTI-LP'}
          user={user}
          overall={overall}
          onMenu={() => setMobileOpen(true)}
          onLogout={logout}
        />

        <main className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-6 sm:px-6 lg:px-8">
          <div key={location.pathname} className="animate-fade-in space-y-5">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}

function StatusRow({ icon, label, ok, value }) {
  return (
    <li className="flex items-center gap-2 text-slate-500">
      <span className="text-slate-600">{icon}</span>
      <span className="flex-1">{label}</span>
      <span
        className={`inline-flex items-center gap-1 font-mono text-[10px] ${
          ok ? 'text-emerald-400' : 'text-amber-400'
        }`}
        title={String(value)}
      >
        <span className={`h-1 w-1 rounded-full ${ok ? 'bg-emerald-400' : 'bg-amber-400'}`} />
        {String(value).slice(0, 10)}
      </span>
    </li>
  );
}

function Sidebar({ items, status, modelOk, overall, mobileOpen, onClose }) {
  return (
    <aside
      className={`fixed inset-y-0 left-0 z-30 w-64 shrink-0 border-r border-slate-800/80 bg-slate-950/85 backdrop-blur-xl transition-transform lg:static lg:translate-x-0 ${
        mobileOpen ? 'translate-x-0' : '-translate-x-full'
      }`}
    >
      <div className="flex h-full flex-col">
        <div className="flex items-center gap-2.5 border-b border-slate-800/80 px-5 py-[18px]">
          <div className="grid h-8 w-8 place-items-center rounded-lg bg-cyan-400/15 text-cyan-300">
            <Icon.Shield size={17} />
          </div>
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold tracking-wide text-slate-100">ACTI-LP</p>
            <p className="truncate text-[10px] uppercase tracking-[0.16em] text-slate-600">
              Threat Intelligence
            </p>
          </div>
          <button
            className="ml-auto rounded p-1 text-slate-500 hover:text-slate-300 lg:hidden"
            onClick={onClose}
            type="button"
            aria-label="Close navigation"
          >
            <Icon.Close size={16} />
          </button>
        </div>

        <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-4">
          <p className="px-2 pb-1.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-600">
            Operations
          </p>
          {items.map((l) => {
            const Glyph = Icon[l.icon];
            return (
              <NavLink
                key={l.to}
                to={l.to}
                end={l.end}
                className={({ isActive }) =>
                  `flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors ${
                    isActive
                      ? 'bg-cyan-400/10 font-medium text-cyan-300 ring-1 ring-inset ring-cyan-400/20'
                      : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-100'
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    <Glyph size={16} className={isActive ? 'text-cyan-300' : 'text-slate-500'} />
                    <span>{l.label}</span>
                    {isActive && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-cyan-400" />}
                  </>
                )}
              </NavLink>
            );
          })}
        </nav>

        <div className="border-t border-slate-800/80 p-3">
          <div className="rounded-lg bg-slate-900/60 p-3">
            <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-600">
              System
            </p>
            <ul className="space-y-1.5 text-[11px]">
              <StatusRow
                icon={<Icon.Cpu size={12} />}
                label="Model"
                ok={modelOk}
                value={status ? (modelOk ? 'ready' : 'degraded') : '…'}
              />
              <StatusRow
                icon={<Icon.Database size={12} />}
                label="Chroma"
                ok={status?.chroma === 'ok'}
                value={status?.chroma ?? '…'}
              />
              <StatusRow icon={<Icon.Shield size={12} />} label="API" ok={overall === 'ok'} value={overall} />
            </ul>
          </div>
        </div>
      </div>
    </aside>
  );
}

function Topbar({ title, user, overall, onMenu, onLogout }) {
  const initials = (user?.full_name || user?.email || '?').slice(0, 2).toUpperCase();
  const tone =
    overall === 'ok'
      ? 'bg-emerald-500/10 text-emerald-300'
      : overall === 'error'
        ? 'bg-red-500/10 text-red-300'
        : 'bg-slate-800 text-slate-400';
  const dot =
    overall === 'ok' ? 'bg-emerald-400' : overall === 'error' ? 'bg-red-400' : 'bg-slate-500';

  return (
    <header className="sticky top-0 z-10 flex items-center gap-3 border-b border-slate-800/80 bg-slate-950/80 px-4 py-3 backdrop-blur-xl sm:px-6">
      <button
        className="rounded-lg border border-slate-800 p-2 text-slate-400 hover:text-slate-100 lg:hidden"
        onClick={onMenu}
        type="button"
        aria-label="Open navigation"
      >
        <Icon.Filter size={16} />
      </button>

      <div className="min-w-0">
        <p className="truncate text-sm font-medium text-slate-200">{title}</p>
        <p className="hidden truncate text-[11px] text-slate-600 sm:block">
          Qwen2.5-0.5B · Outlines guided JSON · local ChromaDB
        </p>
      </div>

      <div className="ml-auto flex items-center gap-3">
        <span
          className={`hidden items-center gap-1.5 rounded-md px-2 py-1 text-[11px] font-medium sm:inline-flex ${tone}`}
        >
          <span className={`h-1.5 w-1.5 rounded-full ${dot}`} />
          {overall === 'ok' ? 'Operational' : overall === 'error' ? 'Degraded' : 'Checking…'}
        </span>

        <div className="flex items-center gap-2.5 border-l border-slate-800 pl-3">
          <div className="hidden text-right leading-tight sm:block">
            <p className="max-w-[180px] truncate text-xs font-medium text-slate-200">
              {user?.full_name || user?.email || 'unknown'}
            </p>
            <p className="text-[10px] uppercase tracking-[0.14em] text-cyan-400/90">{user?.role}</p>
          </div>
          <div className="grid h-8 w-8 place-items-center rounded-full bg-cyan-400/15 text-xs font-semibold text-cyan-300">
            {initials}
          </div>
          <button
            className="rounded-lg p-2 text-slate-500 transition-colors hover:bg-slate-800/70 hover:text-slate-200"
            onClick={onLogout}
            type="button"
            title="Sign out"
            aria-label="Sign out"
          >
            <Icon.Logout size={16} />
          </button>
        </div>
      </div>
    </header>
  );
}

