import { Fragment, useMemo, useState } from 'react';
import { auditApi } from '../api';
import { useFetch } from '../hooks/useFetch';
import Icon from '../components/icons';
import { EmptyState, ErrorNote, PageHeader, TableSkeleton } from '../components/ui';

const fmt = (iso) =>
  iso
    ? new Date(iso).toLocaleString(undefined, {
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
    : '—';

const ACTION_STYLE = (action = '') => {
  if (action.startsWith('auth') || action.includes('login')) return 'bg-cyan-500/10 text-cyan-300';
  if (action.startsWith('user')) return 'bg-violet-500/10 text-violet-300';
  if (action.includes('acknowledge')) return 'bg-amber-500/10 text-amber-300';
  if (action.includes('close')) return 'bg-slate-600/30 text-slate-300';
  return 'bg-slate-700/40 text-slate-300';
};

export default function AuditPage() {
  const { data, loading, error, refresh } = useFetch(
    () => auditApi.list({ limit: 200 }).then((r) => r.data),
    []
  );
  const [action, setAction] = useState('');
  const [query, setQuery] = useState('');
  const [expanded, setExpanded] = useState(null);

  const actions = useMemo(() => Array.from(new Set((data || []).map((r) => r.action))).sort(), [data]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data || []).filter((r) => {
      if (action && r.action !== action) return false;
      if (!q) return true;
      return (
        (r.actor || '').toLowerCase().includes(q) ||
        (r.resource || '').toLowerCase().includes(q) ||
        (String(r.resource_id) || '').toLowerCase().includes(q)
      );
    });
  }, [data, action, query]);

  return (
    <>
      <PageHeader
        title="Audit Trail"
        subtitle="Append-only · immutable record of every privileged action"
        actions={
          <button className="btn-ghost btn-sm" onClick={refresh} disabled={loading} type="button">
            <Icon.Refresh size={14} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        }
      />

      <div className="card flex flex-col gap-3 p-3 lg:flex-row lg:items-center">
        <div className="relative flex-1">
          <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-600">
            <Icon.Search size={15} />
          </span>
          <input
            className="input pl-9"
            placeholder="Filter by actor, resource or id…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Filter audit entries"
          />
        </div>
        <select
          className="input w-auto"
          value={action}
          onChange={(e) => setAction(e.target.value)}
          aria-label="Filter by action"
        >
          <option value="">All actions</option>
          {actions.map((a) => (
            <option key={a} value={a} className="bg-slate-900">
              {a}
            </option>
          ))}
        </select>
        <span className="whitespace-nowrap font-mono text-[11px] text-slate-500">
          {rows.length} / {data?.length ?? 0}
        </span>
      </div>

      <ErrorNote message={error} onRetry={refresh} />

      <div className="card overflow-hidden">
        {loading && !data && <TableSkeleton rows={10} cols={5} />}

        {!loading && !rows.length && (
          <div className="p-6">
            <EmptyState
              title="No audit entries"
              hint="Logins, parses and alert actions are recorded here automatically."
              icon="Audit"
            />
          </div>
        )}

        {!!rows.length && <AuditTable rows={rows} expanded={expanded} onToggle={setExpanded} />}
      </div>
    </>
  );
}

function AuditTable({ rows, expanded, onToggle }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead className="bg-slate-900/80">
          <tr>
            <th className="th w-14">#</th>
            <th className="th">Timestamp</th>
            <th className="th">Actor</th>
            <th className="th">Action</th>
            <th className="th hidden md:table-cell">Resource</th>
            <th className="th w-10" />
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const hasDetail = row.detail && Object.keys(row.detail).length > 0;
            const open = expanded === row.id;
            return (
              <Fragment key={row.id}>
                <tr className="row-hover">
                  <td className="td font-mono text-xs text-slate-600">{row.id}</td>
                  <td className="td whitespace-nowrap font-mono text-[11px] text-slate-400">
                    {fmt(row.created_at)}
                  </td>
                  <td className="td text-xs text-slate-300">{row.actor}</td>
                  <td className="td">
                    <span className={`badge font-mono ${ACTION_STYLE(row.action)}`}>{row.action}</span>
                  </td>
                  <td className="td hidden text-xs text-slate-500 md:table-cell">
                    {row.resource}
                    {row.resource_id ? <span className="text-slate-600"> #{row.resource_id}</span> : null}
                  </td>
                  <td className="td text-right">
                    {hasDetail && (
                      <button
                        className="rounded p-1 text-slate-500 hover:bg-slate-800 hover:text-slate-200"
                        onClick={() => onToggle(open ? null : row.id)}
                        type="button"
                        aria-label={open ? 'Collapse detail' : 'Expand detail'}
                      >
                        {open ? <Icon.ChevronDown size={14} /> : <Icon.ChevronRight size={14} />}
                      </button>
                    )}
                  </td>
                </tr>
                {open && hasDetail && (
                  <tr className="bg-slate-950/60">
                    <td colSpan={6} className="px-4 py-3">
                      <pre className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900/70 p-3 font-mono text-[11px] text-slate-400">
                        {JSON.stringify(row.detail, null, 2)}
                      </pre>
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
