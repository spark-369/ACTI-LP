import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useDashboard } from '../hooks/useDashboard';
import { AttackTypeChart, SeverityChart, TimelineChart } from '../components/Charts';
import Icon from '../components/icons';
import {
  EmptyState,
  ErrorNote,
  PageHeader,
  SeverityBadge,
  Skeleton,
  StatCard,
  StatusBadge,
} from '../components/ui';
import { alertsApi } from '../api';
import { useFetch } from '../hooks/useFetch';

const fmt = (iso) =>
  iso
    ? new Date(iso).toLocaleString(undefined, {
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
      })
    : '—';

export default function DashboardPage() {
  const { stats, loading, error, refresh } = useDashboard(7);

  // Recent critical/high alerts that still need attention.
  const { data: openCritical } = useFetch(
    () => alertsApi.list({ limit: 6, status: 'new', severity: 'critical' }).then((r) => r.data.items),
    []
  );
  const { data: recent } = useFetch(() => alertsApi.list({ limit: 6 }).then((r) => r.data.items), []);

  const openList = useMemo(
    () => (openCritical?.length ? openCritical : recent || []),
    [openCritical, recent]
  );

  const detectionRate = useMemo(() => {
    if (!stats || !stats.total_alerts) return 0;
    return Math.round((stats.malicious / stats.total_alerts) * 100);
  }, [stats]);

  return (
    <>
      <PageHeader
        title="Threat Overview"
        subtitle="Last 7 days · tenant-scoped telemetry"
        actions={
          <>
            <Link to="/parse" className="btn-ghost btn-sm">
              <Icon.Terminal size={14} />
              Parse a log
            </Link>
            <button className="btn-ghost btn-sm" onClick={refresh} disabled={loading} type="button">
              <Icon.Refresh size={14} className={loading ? 'animate-spin' : ''} />
              Refresh
            </button>
          </>
        }
      />

      <ErrorNote message={error} onRetry={refresh} />

      {!stats && loading && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="card card-pad space-y-3">
              <Skeleton className="h-3 w-24" />
              <Skeleton className="h-8 w-16" />
              <Skeleton className="h-3 w-20" />
            </div>
          ))}
        </div>
      )}

      {stats && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <StatCard label="Total alerts" value={stats.total_alerts} icon="Inbox" hint="all time" />
          <StatCard
            label="Malicious"
            value={stats.malicious}
            accent="text-red-400"
            icon="Alert"
            hint={`${detectionRate}% detection rate`}
          />
          <StatCard
            label="Awaiting triage"
            value={stats.open_alerts}
            accent="text-cyan-300"
            icon="Filter"
            hint="status = new"
          />
          <StatCard
            label="Critical open"
            value={stats.critical_open}
            accent="text-orange-400"
            icon="Shield"
            hint="needs immediate review"
          />
        </div>
      )}

      {stats && (
        <>
          <div className="grid gap-4 lg:grid-cols-3">
            <section className="card lg:col-span-2">
              <div className="card-header">
                <p className="card-title">Alerts per day</p>
                <span className="font-mono text-[11px] text-slate-500">7d</span>
              </div>
              <div className="p-3">
                <TimelineChart data={stats.timeline} />
              </div>
            </section>

            <section className="card">
              <div className="card-header">
                <p className="card-title">Severity distribution</p>
              </div>
              <div className="p-3">
                <SeverityChart data={stats.by_severity} />
              </div>
            </section>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <section className="card">
              <div className="card-header">
                <p className="card-title">Top attack types</p>
                <span className="font-mono text-[11px] text-slate-500">
                  {stats.by_attack_type.length} categories
                </span>
              </div>
              <div className="p-3">
                {stats.by_attack_type.length ? (
                  <AttackTypeChart data={stats.by_attack_type} />
                ) : (
                  <EmptyState
                    title="No malicious activity yet"
                    hint="Submit a log from the Parse page to populate this chart."
                    icon="Alert"
                    action={
                      <Link to="/parse" className="btn-primary btn-sm">
                        <Icon.Play size={13} />
                        Parse a log
                      </Link>
                    }
                  />
                )}
              </div>
            </section>

            <section className="card">
              <div className="card-header">
                <p className="card-title">Needs attention</p>
                <Link
                  to="/alerts"
                  className="inline-flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300"
                >
                  View all
                  <Icon.ChevronRight size={12} />
                </Link>
              </div>
              <div className="divide-y divide-slate-800/70">
                {!openList?.length && (
                  <div className="p-4">
                    <EmptyState title="Nothing open" hint="All alerts have been triaged." icon="Check" />
                  </div>
                )}
                {openList?.map((a) => (
                  <Link
                    key={a.id}
                    to="/alerts"
                    className="flex items-start gap-3 px-5 py-3 transition-colors hover:bg-slate-800/40"
                  >
                    <div className="mt-0.5">
                      <SeverityBadge severity={a.severity} />
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium capitalize text-slate-200">
                        {a.attack_type.replace(/_/g, ' ')}
                      </p>
                      <p className="truncate text-[11px] text-slate-500">{a.summary}</p>
                    </div>
                    <div className="flex shrink-0 flex-col items-end gap-1">
                      <StatusBadge status={a.status} />
                      <span className="font-mono text-[10px] text-slate-600">{fmt(a.created_at)}</span>
                    </div>
                  </Link>
                ))}
              </div>
            </section>
          </div>
        </>
      )}
    </>
  );
}
