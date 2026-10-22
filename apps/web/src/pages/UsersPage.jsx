import { useMemo, useState } from 'react';
import { usersApi } from '../api';
import { useFetch } from '../hooks/useFetch';
import { apiErrorMessage } from '../api/client';
import Icon from '../components/icons';
import { EmptyState, ErrorNote, PageHeader, TableSkeleton } from '../components/ui';

const emptyForm = { email: '', password: '', full_name: '', role: 'analyst' };

const ROLE_STYLE = {
  admin: 'bg-red-500/10 text-red-300 ring-1 ring-inset ring-red-500/25',
  analyst: 'bg-cyan-500/10 text-cyan-300 ring-1 ring-inset ring-cyan-500/25',
  viewer: 'bg-slate-600/25 text-slate-300 ring-1 ring-inset ring-slate-500/30',
};

const initials = (u) => (u.full_name || u.email || '?').slice(0, 2).toUpperCase();

export default function UsersPage() {
  const { data: users, loading, error, refresh } = useFetch(
    () => usersApi.list().then((r) => r.data),
    []
  );
  const [form, setForm] = useState(emptyForm);
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState(null);
  const [query, setQuery] = useState('');

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return users || [];
    return (users || []).filter(
      (u) => u.email.toLowerCase().includes(q) || (u.full_name || '').toLowerCase().includes(q)
    );
  }, [users, query]);

  const counts = useMemo(() => {
    const base = { admin: 0, analyst: 0, viewer: 0 };
    (users || []).forEach((u) => {
      base[u.role] = (base[u.role] || 0) + 1;
    });
    return base;
  }, [users]);

  const submit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setFormError(null);
    try {
      await usersApi.create(form);
      setForm(emptyForm);
      await refresh();
    } catch (err) {
      setFormError(apiErrorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const deactivate = async (id) => {
    setBusy(true);
    setFormError(null);
    try {
      await usersApi.deactivate(id);
      await refresh();
    } catch (err) {
      setFormError(apiErrorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeader
        title="Users & Roles"
        subtitle="DB-driven RBAC · tenant-scoped access control"
        actions={
          <button className="btn-ghost btn-sm" onClick={refresh} disabled={loading} type="button">
            <Icon.Refresh size={14} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        }
      />

      <div className="grid gap-4 sm:grid-cols-3">
        {['admin', 'analyst', 'viewer'].map((r) => (
          <div key={r} className="card card-pad">
            <p className="card-title">{r}</p>
            <p className="mt-2 font-mono text-2xl font-semibold text-slate-100">{counts[r] || 0}</p>
            <p className="mt-1 text-[11px] text-slate-500">
              {r === 'admin' ? 'full access' : r === 'analyst' ? 'read + parse + ack' : 'read only'}
            </p>
          </div>
        ))}
      </div>

      <ErrorNote message={error} onRetry={refresh} />
      <ErrorNote message={formError} />

      <div className="grid gap-5 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <div className="card">
            <div className="card-header">
              <p className="card-title">Tenant members</p>
              <div className="relative w-56">
                <span className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-600">
                  <Icon.Search size={13} />
                </span>
                <input
                  className="input py-1.5 pl-8 text-xs"
                  placeholder="Filter by email or name"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  aria-label="Filter users"
                />
              </div>
            </div>
            {loading && !users && <TableSkeleton rows={5} cols={4} />}
            {!loading && !filtered.length && (
              <div className="p-6">
                <EmptyState
                  title={query ? 'No users match that filter' : 'No users yet'}
                  hint={query ? 'Try a different email or name.' : 'Create the first analyst account.'}
                  icon="Users"
                />
              </div>
            )}
            {!!filtered.length && (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-slate-900/80">
                    <tr>
                      <th className="th">User</th>
                      <th className="th">Role</th>
                      <th className="th hidden sm:table-cell">Status</th>
                      <th className="th hidden md:table-cell">Last login</th>
                      <th className="th text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((u) => (
                      <tr key={u.id} className="row-hover">
                        <td className="td">
                          <div className="flex items-center gap-3">
                            <div className="grid h-8 w-8 shrink-0 place-items-center rounded-full bg-slate-800 text-[11px] font-semibold text-slate-300">
                              {initials(u)}
                            </div>
                            <div className="min-w-0">
                              <p className="truncate text-sm font-medium text-slate-200">
                                {u.full_name || '—'}
                              </p>
                              <p className="truncate text-[11px] text-slate-500">{u.email}</p>
                            </div>
                          </div>
                        </td>
                        <td className="td">
                          <span className={`badge ${ROLE_STYLE[u.role] || ROLE_STYLE.viewer}`}>{u.role}</span>
                        </td>
                        <td className="td hidden sm:table-cell">
                          <span
                            className={`inline-flex items-center gap-1.5 text-xs ${
                              u.is_active ? 'text-emerald-400' : 'text-slate-500'
                            }`}
                          >
                            <span
                              className={`h-1.5 w-1.5 rounded-full ${
                                u.is_active ? 'bg-emerald-400' : 'bg-slate-600'
                              }`}
                            />
                            {u.is_active ? 'active' : 'disabled'}
                          </span>
                        </td>
                        <td className="td hidden font-mono text-[11px] text-slate-500 md:table-cell">
                          {u.last_login_at
                            ? new Date(u.last_login_at).toLocaleDateString(undefined, {
                                month: 'short',
                                day: '2-digit',
                              })
                            : 'never'}
                        </td>
                        <td className="td text-right">
                          {u.is_active ? (
                            <button
                              className="text-xs text-red-400 hover:text-red-300 disabled:opacity-40"
                              onClick={() => deactivate(u.id)}
                              disabled={busy}
                              type="button"
                            >
                              Deactivate
                            </button>
                          ) : (
                            <span className="text-xs text-slate-600">—</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        <form onSubmit={submit} className="card h-fit">
          <div className="card-header">
            <p className="card-title">Create user</p>
            <Icon.Plus size={14} className="text-slate-500" />
          </div>

          <div className="space-y-3 p-4">
            <div>
              <label className="label" htmlFor="u-email">Email</label>
              <input
                id="u-email"
                className="input"
                type="email"
                autoComplete="off"
                value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })}
                required
              />
            </div>
            <div>
              <label className="label" htmlFor="u-name">Full name</label>
              <input
                id="u-name"
                className="input"
                value={form.full_name}
                onChange={(e) => setForm({ ...form, full_name: e.target.value })}
              />
            </div>
            <div>
              <label className="label" htmlFor="u-pass">Password</label>
              <input
                id="u-pass"
                className="input"
                type="password"
                autoComplete="new-password"
                minLength={8}
                value={form.password}
                onChange={(e) => setForm({ ...form, password: e.target.value })}
                required
              />
              <p className="mt-1 text-[11px] text-slate-600">Minimum 8 characters.</p>
            </div>
            <div>
              <label className="label" htmlFor="u-role">Role</label>
              <select
                id="u-role"
                className="input"
                value={form.role}
                onChange={(e) => setForm({ ...form, role: e.target.value })}
              >
                <option value="viewer">viewer — read only</option>
                <option value="analyst">analyst — read + parse + ack</option>
                <option value="admin">admin — full access</option>
              </select>
            </div>

            <button className="btn-primary w-full" type="submit" disabled={busy}>
              <Icon.Plus size={14} />
              {busy ? 'Saving…' : 'Create user'}
            </button>
          </div>
        </form>
      </div>
    </>
  );
}
