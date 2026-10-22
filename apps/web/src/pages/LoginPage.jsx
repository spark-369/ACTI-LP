import { useState } from 'react';
import { useAuthStore } from '../store/authStore';
import { ErrorNote } from '../components/ui';
import Icon from '../components/icons';

const HIGHLIGHTS = [
  { icon: 'Cpu', title: 'Local inference', desc: 'Qwen2.5-0.5B runs on CPU — no data leaves the host.' },
  { icon: 'Database', title: 'Schema-locked output', desc: 'Outlines constrains decoding to a versioned JSON schema.' },
  { icon: 'Shield', title: 'Tenant-isolated', desc: 'JWT + RBAC with per-tenant vector collections.' },
];

export default function LoginPage() {
  const { login, loading, error } = useAuthStore();
  const [email, setEmail] = useState('admin@actilp.local');
  const [password, setPassword] = useState('');

  const onSubmit = async (event) => {
    event.preventDefault();
    if (!email.trim() || !password) return; // avoid a pointless 422 round-trip
    try {
      await login(email.trim(), password);
    } catch {
      /* error surfaced via store */
    }
  };

  return (
    <div className="grid min-h-screen lg:grid-cols-2">
      {/* Brand panel */}
      <div className="relative hidden flex-col justify-between border-r border-slate-800/80 p-10 lg:flex">
        <div className="flex items-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-xl bg-cyan-400/15 text-cyan-300">
            <Icon.Shield size={20} />
          </div>
          <div>
            <p className="text-sm font-semibold tracking-wide text-slate-100">ACTI-LP</p>
            <p className="text-[10px] uppercase tracking-[0.18em] text-slate-600">
              Automated Cyber Threat Intelligence
            </p>
          </div>
        </div>

        <div className="max-w-md">
          <h2 className="text-2xl font-semibold leading-snug tracking-tight text-slate-100">
            Turn raw logs into triage-ready threat intelligence.
          </h2>
          <p className="mt-3 text-sm leading-relaxed text-slate-500">
            Every log line is embedded, matched against tenant history and classified by a constrained
            local model — deterministically shaped, never leaving your infrastructure.
          </p>

          <ul className="mt-8 space-y-4">
            {HIGHLIGHTS.map((h) => {
              const Glyph = Icon[h.icon];
              return (
                <li key={h.title} className="flex gap-3">
                  <span className="mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-slate-800/70 text-cyan-300">
                    <Glyph size={15} />
                  </span>
                  <div>
                    <p className="text-sm font-medium text-slate-200">{h.title}</p>
                    <p className="text-xs leading-relaxed text-slate-500">{h.desc}</p>
                  </div>
                </li>
              );
            })}
          </ul>
        </div>

        <p className="text-[11px] text-slate-700">
          Prompt injection mitigated by schema validation · telemetry disabled
        </p>
      </div>

      {/* Form panel */}
      <div className="grid place-items-center px-4 py-12">
        <div className="w-full max-w-sm">
          <div className="mb-7 lg:hidden">
            <div className="mb-3 grid h-12 w-12 place-items-center rounded-2xl bg-cyan-400/15 text-cyan-300">
              <Icon.Shield size={22} />
            </div>
            <p className="text-base font-semibold text-slate-100">ACTI-LP</p>
            <p className="text-xs text-slate-500">Threat Intelligence &amp; Log Parser</p>
          </div>

          <h1 className="text-lg font-semibold tracking-tight text-slate-100">Sign in</h1>
          <p className="mt-1 text-xs text-slate-500">Use your tenant account to continue.</p>

          <form onSubmit={onSubmit} className="mt-6 space-y-4">
            <div>
              <label className="label" htmlFor="email">
                Email
              </label>
              <input
                id="email"
                className="input"
                type="email"
                autoComplete="username"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="label" htmlFor="password">
                Password
              </label>
              <input
                id="password"
                className="input"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>

            <ErrorNote message={error} />

            <button
              className="btn-primary w-full"
              type="submit"
              disabled={loading || !email.trim() || !password}
            >
              {loading ? (
                <>
                  <Icon.Refresh size={14} className="animate-spin" />
                  Signing in…
                </>
              ) : (
                <>
                  Sign in
                  <Icon.ChevronRight size={14} />
                </>
              )}
            </button>
          </form>

          <p className="mt-6 text-center text-[11px] leading-relaxed text-slate-600">
            Bootstrap credentials are configured in <code className="text-slate-500">apps/api/.env</code>
          </p>
        </div>
      </div>
    </div>
  );
}

