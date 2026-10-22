import { useEffect, useMemo, useState } from 'react';
import { useAlerts } from '../hooks/useAlerts';
import { useAuthStore } from '../store/authStore';
import Icon from '../components/icons';
import {
  CountPill,
  EmptyState,
  ErrorNote,
  PageHeader,
  SeverityBadge,
  StatusBadge,
  TableSkeleton,
} from '../components/ui';

const fmt = (iso) =>
  iso
    ? new Date(iso).toLocaleString(undefined, {
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
      })
    : '—';

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low'];

// Raw parser_mode values are internal identifiers; show something an analyst
// can act on. A fallback parser is materially less accurate, so it is surfaced
// as a warning rather than a neutral label.
const PARSER_LABEL = {
  outlines: 'LLM (Outlines)',
  fallback: 'Regex fallback',
  celery: 'Queued (Celery)',
};
const STATUSES = [
  { value: '', label: 'All' },
  { value: 'new', label: 'New' },
  { value: 'acknowledged', label: 'Acknowledged' },
  { value: 'closed', label: 'Closed' },
];

export default function AlertsPage() {
  const { user } = useAuthStore();
  const canAct = ['admin', 'analyst'].includes(user?.role);

  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState(null);

  const params = useMemo(() => {
    const p = { limit: 100 };
    if (severity) p.severity = severity;
    if (status) p.status = status;
    if (search.trim()) p.search = search.trim();
    return p;
  }, [severity, status, search]);

  const { data, total, loading, error, refresh, acknowledge, close } = useAlerts(params);

  const run = async (fn, id) => {
    setBusy(true);
    setActionError(null);
    try {
      await fn(id);
      setSelected(null);
    } catch (e) {
      setActionError(e?.response?.data?.detail || 'Action failed');
    } finally {
      setBusy(false);
    }
  };

  const activeFilters = [severity, status, search.trim()].filter(Boolean).length;

  return (
    <>
      <PageHeader
        title="Alerts"
        subtitle={`${total} alert${total === 1 ? '' : 's'} in tenant · newest first`}
        actions={
          <button className="btn-ghost btn-sm" onClick={refresh} disabled={loading} type="button">
            <Icon.Refresh size={14} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        }
      />

      <div className="card">
        <div className="flex flex-col gap-3 border-b border-slate-800/80 p-3 lg:flex-row lg:items-center">
          <div className="relative flex-1">
            <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-600">
              <Icon.Search size={15} />
            </span>
            <input
              className="input pl-9"
              placeholder="Search raw log, summary or attack type…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              aria-label="Search alerts"
            />
          </div>

          <div className="flex items-center gap-2">
            <select
              className="input w-auto"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              aria-label="Filter by severity"
            >
              {SEVERITIES.map((s) => (
                <option key={s || 'all'} value={s} className="bg-slate-900">
                  {s || 'All severities'}
                </option>
              ))}
            </select>

            {activeFilters > 0 && (
              <button
                className="btn-ghost btn-sm"
                type="button"
                onClick={() => {
                  setSeverity('');
                  setStatus('');
                  setSearch('');
                }}
              >
                <Icon.Close size={13} />
                Clear
              </button>
            )}
          </div>
        </div>

        <div className="flex items-center gap-1 overflow-x-auto px-3 py-2">
          {STATUSES.map((s) => {
            const active = status === s.value;
            return (
              <button
                key={s.value || 'all'}
                type="button"
                onClick={() => setStatus(s.value)}
                className={`whitespace-nowrap rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
                  active
                    ? 'bg-cyan-400/10 text-cyan-300 ring-1 ring-inset ring-cyan-400/25'
                    : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
                }`}
              >
                {s.label}
                {active && total > 0 && <CountPill active>{total}</CountPill>}
              </button>
            );
          })}
        </div>
      </div>

      <ErrorNote message={error} onRetry={refresh} />
      <ErrorNote message={actionError} />

      <div className="card overflow-hidden">
        {loading && !data.length && <TableSkeleton rows={8} cols={6} />}

        {!loading && !data.length && (
          <div className="p-6">
            <EmptyState
              title="No alerts match the current filters"
              hint="Adjust the filters above, or parse a new log to create an alert."
              icon="Inbox"
            />
          </div>
        )}

        {!!data.length && (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-900/80">
                <tr>
                  <th className="th w-14">ID</th>
                  <th className="th">Severity</th>
                  <th className="th">Attack</th>
                  <th className="th hidden md:table-cell">MITRE</th>
                  <th className="th">Status</th>
                  <th className="th hidden sm:table-cell">Conf.</th>
                  <th className="th hidden lg:table-cell">Parser</th>
                  <th className="th text-right">Detected</th>
                </tr>
              </thead>
              <tbody>
                {data.map((a) => (
                  <tr
                    key={a.id}
                    onClick={() => setSelected(a)}
                    className={`row-hover cursor-pointer ${selected?.id === a.id ? 'bg-slate-800/70' : ''}`}
                  >
                    <td className="td font-mono text-xs text-slate-600">#{a.id}</td>
                    <td className="td">
                      <SeverityBadge severity={a.severity} />
                    </td>
                    <td className="td">
                      <p className="font-medium capitalize text-slate-200">
                        {a.attack_type.replace(/_/g, ' ')}
                      </p>
                      <p className="max-w-[38ch] truncate text-[11px] text-slate-500">{a.summary}</p>
                    </td>
                    <td className="td hidden max-w-[18ch] md:table-cell">
                      {a.mitre_tactic ? (
                        <span className="text-xs text-slate-400" title={a.mitre_tactic}>
                          {a.mitre_tactic.replace(/^TA\d+\s*-\s*/, '')}
                        </span>
                      ) : (
                        <span className="text-xs text-slate-600">
                          {a.is_malicious ? 'Not mapped' : '—'}
                        </span>
                      )}
                    </td>
                    <td className="td">
                      <StatusBadge status={a.status} />
                    </td>
                    <td className="td hidden font-mono text-xs sm:table-cell">
                      <span
                        className={
                          a.confidence >= 0.7
                            ? 'text-emerald-400'
                            : a.confidence >= 0.4
                              ? 'text-amber-400'
                              : 'text-slate-500'
                        }
                      >
                        {Number(a.confidence).toFixed(2)}
                      </span>
                    </td>
                    <td className="td hidden lg:table-cell">
                      <span
                        className={`badge ${
                          a.parser_mode === 'outlines'
                            ? 'bg-cyan-500/10 text-cyan-300'
                            : 'bg-amber-500/10 text-amber-300'
                        }`}
                        title={
                          a.parser_mode === 'outlines'
                            ? 'Produced by the local Qwen model under Outlines constrained decoding'
                            : 'Model unavailable — produced by the regex fallback and less reliable'
                        }
                      >
                        {PARSER_LABEL[a.parser_mode] || a.parser_mode}
                      </span>
                    </td>
                    <td className="td whitespace-nowrap text-right font-mono text-[11px] text-slate-500">
                      {fmt(a.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selected && (
        <AlertDrawer
          alert={selected}
          canAct={canAct}
          busy={busy}
          onClose={() => setSelected(null)}
          onAcknowledge={() => run(acknowledge, selected.id)}
          onCloseAlert={() => run(close, selected.id)}
        />
      )}
    </>
  );
}

function AlertDrawer({ alert, canAct, busy, onClose, onAcknowledge, onCloseAlert }) {
  // Lock background scrolling while the drawer is open. Without this the page
  // behind still scrolls on touch devices, which makes the drawer appear to
  // jump and lets content slide under the fixed overlay.
  useEffect(() => {
    const previous = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = previous;
    };
  }, []);

  // Escape closes the dialog.
  useEffect(() => {
    const onKey = (event) => {
      if (event.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-40 flex justify-end p-4 sm:p-6">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} aria-hidden="true" />
      <aside
        role="dialog"
        aria-label={`Alert ${alert.id} details`}
        className="animate-slide-in relative flex max-h-[75vh] w-full max-w-lg flex-col overflow-hidden rounded-xl border border-slate-800 bg-slate-950 shadow-2xl"
      >
        {/* shrink-0: the header must not collapse when the body scrolls. */}
        <div className="flex shrink-0 items-start justify-between gap-3 border-b border-slate-800 px-5 py-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={alert.severity} />
              <StatusBadge status={alert.status} />
              <span className="font-mono text-[11px] text-slate-600">#{alert.id}</span>
            </div>
            <h2 className="mt-2 truncate text-base font-semibold capitalize text-slate-100">
              {alert.attack_type.replace(/_/g, ' ')}
            </h2>
          </div>
          <button
            className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-800 hover:text-slate-200"
            onClick={onClose}
            type="button"
            aria-label="Close details"
          >
            <Icon.Close size={16} />
          </button>
        </div>

        {/* min-h-0 is required: a flex child defaults to min-height:auto and
            will not shrink below its content, which pushed the action bar off
            screen for long logs. */}
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
          <section>
            <p className="label">Analyst summary</p>
            <p className="text-sm leading-relaxed text-slate-300">{alert.summary}</p>
          </section>

          <section className="grid grid-cols-2 gap-3 text-sm">
            <Field
              label="MITRE tactic"
              value={alert.mitre_tactic || (alert.is_malicious ? 'Not mapped' : 'Not applicable')}
              muted={!alert.mitre_tactic}
            />
            <Field label="Confidence" value={Number(alert.confidence).toFixed(2)} mono />
            <Field
              label="Parser"
              value={PARSER_LABEL[alert.parser_mode] || alert.parser_mode}
              accent={alert.parser_mode !== 'outlines'}
            />
            <Field label="Source" value={alert.source} />
            <Field label="Model" value={alert.model_id || '—'} mono truncate />
            <Field label="Detected" value={fmt(alert.created_at)} />
            <Field
              label="Acknowledged by"
              value={alert.acknowledged_by || 'Not acknowledged'}
              muted={!alert.acknowledged_by}
              truncate
            />
            <Field
              label="Acknowledged at"
              value={alert.acknowledged_at ? fmt(alert.acknowledged_at) : '—'}
              muted={!alert.acknowledged_at}
            />
          </section>

          <section>
            <p className="label">
              Indicators of compromise <span className="text-slate-600">({alert.iocs.length})</span>
            </p>
            {alert.iocs.length ? (
              <div className="flex flex-wrap gap-1.5">
                {alert.iocs.map((ioc) => (
                  <code key={ioc} className="chip text-cyan-300">
                    {ioc}
                  </code>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-600">No indicators were extracted.</p>
            )}
          </section>

          <section>
            <p className="label">Raw log</p>
            {/* No inner max-height: the drawer body already scrolls, and a
                nested scroll region hid most of the log on small screens. */}
            <pre className="max-h-[18vh] overflow-auto whitespace-pre-wrap break-words rounded-lg border border-slate-800 bg-slate-900/70 p-3 font-mono text-[11px] leading-relaxed text-slate-400">
              {alert.raw_log}
            </pre>
          </section>
        </div>

        <div className="flex shrink-0 gap-2 border-t border-slate-800 bg-slate-950 px-5 py-3">
          {canAct ? (
            <>
              <button
                className="btn-primary flex-1"
                type="button"
                disabled={busy || alert.status !== 'new'}
                onClick={onAcknowledge}
              >
                <Icon.Check size={14} />
                Acknowledge
              </button>
              <button
                className="btn-danger flex-1"
                type="button"
                disabled={busy || alert.status === 'closed'}
                onClick={onCloseAlert}
              >
                Close alert
              </button>
            </>
          ) : (
            <p className="text-xs text-slate-500">
              Your role is read-only; an analyst or admin can action this alert.
            </p>
          )}
        </div>
      </aside>
    </div>
  );
}

function Field({ label, value, mono = false, accent = false, truncate = false, muted = false }) {
  return (
    <div className="min-w-0">
      <p className="text-[10px] uppercase tracking-[0.12em] text-slate-600">{label}</p>
      <p
        className={`${mono ? 'font-mono text-xs' : 'text-sm'} ${
          accent ? 'text-amber-400' : muted ? 'text-slate-500' : 'text-slate-200'
        } ${truncate ? 'truncate' : ''}`}
        title={typeof value === 'string' ? value : undefined}
      >
        {value}
      </p>
    </div>
  );
}
