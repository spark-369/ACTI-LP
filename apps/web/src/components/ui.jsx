import Icon from './icons';

export function SeverityBadge({ severity }) {
  const map = {
    critical: 'bg-red-500/10 text-red-300 ring-1 ring-inset ring-red-500/25',
    high: 'bg-orange-500/10 text-orange-300 ring-1 ring-inset ring-orange-500/25',
    medium: 'bg-amber-400/10 text-amber-300 ring-1 ring-inset ring-amber-400/25',
    low: 'bg-emerald-500/10 text-emerald-300 ring-1 ring-inset ring-emerald-500/25',
  };
  const dot = {
    critical: 'bg-red-400',
    high: 'bg-orange-400',
    medium: 'bg-amber-400',
    low: 'bg-emerald-400',
  };
  return (
    <span className={`badge ${map[severity] || 'bg-slate-700/50 text-slate-300'}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${dot[severity] || 'bg-slate-400'}`} />
      {severity}
    </span>
  );
}

export function StatusBadge({ status }) {
  const map = {
    new: 'bg-cyan-500/10 text-cyan-300 ring-1 ring-inset ring-cyan-500/25',
    acknowledged: 'bg-amber-500/10 text-amber-300 ring-1 ring-inset ring-amber-500/25',
    closed: 'bg-slate-700/40 text-slate-400 ring-1 ring-inset ring-slate-600/40',
  };
  return <span className={`badge ${map[status] || 'bg-slate-700/50 text-slate-300'}`}>{status}</span>;
}

export function Spinner({ label = 'Loading…', size = 16 }) {
  return (
    <div className="flex items-center gap-2.5 text-sm text-slate-400">
      <span
        className="animate-spin rounded-full border-2 border-slate-700 border-t-cyan-400"
        style={{ width: size, height: size }}
      />
      {label}
    </div>
  );
}

export function ErrorNote({ message, onRetry }) {
  if (!message) return null;
  // Defensive: FastAPI 422 details are arrays/objects — never render them raw.
  const text =
    typeof message === 'string' ? message : Array.isArray(message) ? message.join('; ') : String(message);
  return (
    <div
      role="alert"
      className="flex items-start justify-between gap-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3.5 py-2.5 text-sm text-red-200"
    >
      <div className="flex items-start gap-2">
        <Icon.Alert size={15} className="mt-0.5 shrink-0 text-red-400" />
        <span className="leading-snug">{text}</span>
      </div>
      {onRetry && (
        <button className="btn-ghost btn-sm shrink-0" onClick={onRetry} type="button">
          Retry
        </button>
      )}
    </div>
  );
}

export function EmptyState({ title, hint, icon = 'Inbox', action }) {
  const Glyph = Icon[icon] || Icon.Inbox;
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-slate-800 px-6 py-12 text-center">
      <div className="grid h-11 w-11 place-items-center rounded-full bg-slate-800/60 text-slate-500">
        <Glyph size={20} />
      </div>
      <div>
        <p className="text-sm font-medium text-slate-300">{title}</p>
        {hint && <p className="mx-auto mt-1 max-w-sm text-xs leading-relaxed text-slate-500">{hint}</p>}
      </div>
      {action}
    </div>
  );
}

export function Skeleton({ className = 'h-4 w-full' }) {
  return <div className={`skeleton ${className}`} />;
}

export function TableSkeleton({ rows = 6, cols = 5 }) {
  return (
    <div className="space-y-2 p-4">
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex gap-3">
          {Array.from({ length: cols }).map((__, c) => (
            <Skeleton key={c} className={`h-5 ${c === 0 ? 'w-10' : 'flex-1'}`} />
          ))}
        </div>
      ))}
    </div>
  );
}

/** KPI tile with optional trend + accent. */
export function StatCard({ label, value, hint, accent = 'text-slate-100', icon, trend }) {
  const Glyph = icon ? Icon[icon] : null;
  return (
    <div className="card card-pad">
      <div className="flex items-start justify-between">
        <p className="card-title">{label}</p>
        {Glyph && (
          <span className="grid h-7 w-7 place-items-center rounded-md bg-slate-800/70 text-slate-500">
            <Glyph size={14} />
          </span>
        )}
      </div>
      <p className={`mt-2 font-mono text-3xl font-semibold tracking-tight ${accent}`}>{value}</p>
      <div className="mt-1 flex items-center gap-2">
        {trend !== undefined && trend !== null && (
          <span
            className={`text-[11px] font-semibold ${
              trend > 0 ? 'text-red-400' : trend < 0 ? 'text-emerald-400' : 'text-slate-500'
            }`}
          >
            {trend > 0 ? '▲' : trend < 0 ? '▼' : '■'} {Math.abs(trend)}
          </span>
        )}
        {hint && <p className="text-[11px] text-slate-500">{hint}</p>}
      </div>
    </div>
  );
}

/** Page header used by every screen. */
export function PageHeader({ title, subtitle, actions }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-slate-100">{title}</h1>
        {subtitle && <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

/** Small coloured count pill for filter tabs. */
export function CountPill({ children, active }) {
  return (
    <span
      className={`ml-1.5 rounded px-1.5 py-0.5 font-mono text-[10px] ${
        active ? 'bg-cyan-400/20 text-cyan-200' : 'bg-slate-700/50 text-slate-400'
      }`}
    >
      {children}
    </span>
  );
}

