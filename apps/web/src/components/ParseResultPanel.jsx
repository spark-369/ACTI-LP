import { SeverityBadge } from './ui';
import Icon from './icons';

export default function ParseResultPanel({ result }) {
  if (!result) {
    return (
      <div className="flex flex-col items-center gap-3 py-10 text-center">
        <div className="grid h-11 w-11 place-items-center rounded-full bg-slate-800/60 text-slate-500">
          <Icon.Terminal size={20} />
        </div>
        <div>
          <p className="text-sm font-medium text-slate-300">Awaiting input</p>
          <p className="mt-1 max-w-xs text-xs leading-relaxed text-slate-500">
            Submit a log line to see the schema-validated threat analysis produced by the local model.
          </p>
        </div>
      </div>
    );
  }

  const r = result.result;
  const confidence = Number(r.confidence) || 0;
  const pct = Math.round(confidence * 100);
  const isOutlines = result.parser_mode === 'outlines';

  return (
    <div className="space-y-5">
      <div
        className={`flex items-center gap-3 rounded-lg border px-3.5 py-3 ${
          r.is_malicious
            ? 'border-red-500/30 bg-red-500/10'
            : 'border-emerald-500/25 bg-emerald-500/10'
        }`}
      >
        <div
          className={`grid h-9 w-9 shrink-0 place-items-center rounded-full ${
            r.is_malicious ? 'bg-red-500/15 text-red-400' : 'bg-emerald-500/15 text-emerald-400'
          }`}
        >
          {r.is_malicious ? <Icon.Alert size={17} /> : <Icon.Check size={17} />}
        </div>
        <div className="min-w-0 flex-1">
          <p className={`text-sm font-semibold ${r.is_malicious ? 'text-red-200' : 'text-emerald-200'}`}>
            {r.is_malicious ? 'Malicious activity detected' : 'No malicious activity detected'}
          </p>
          <p className="truncate text-[11px] capitalize text-slate-400">
            {String(r.attack_type).replace(/_/g, ' ')} · {r.severity}
          </p>
        </div>
        <SeverityBadge severity={r.severity} />
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <span
          className={`badge ${isOutlines ? 'bg-cyan-500/10 text-cyan-300' : 'bg-amber-500/10 text-amber-300'}`}
          title={
            isOutlines
              ? 'Analysis produced by the local Qwen model under Outlines constrained decoding'
              : 'Model unavailable — analysis produced by the regex fallback and is less reliable'
          }
        >
          <Icon.Cpu size={11} />
          {result.parser_mode === 'outlines' ? 'LLM (Outlines)' : 'Regex fallback'}
        </span>
        {result.alert_id && <span className="chip">alert #{result.alert_id}</span>}
        {result.task_id && <span className="chip text-amber-300">task {result.task_id.slice(0, 8)}</span>}
        {result.model_id && (
          <span className="chip max-w-[220px] truncate" title={result.model_id}>
            {result.model_id}
          </span>
        )}
      </div>

      <div>
        <div className="mb-1.5 flex items-center justify-between">
          <p className="label mb-0">Confidence</p>
          <span className="font-mono text-xs text-slate-300">{confidence.toFixed(2)}</span>
        </div>
        <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
          <div
            className={`h-full rounded-full transition-all ${
              confidence >= 0.7 ? 'bg-emerald-400' : confidence >= 0.4 ? 'bg-amber-400' : 'bg-slate-500'
            }`}
            style={{ width: `${pct}%` }}
          />
        </div>
      </div>

      <dl className="grid grid-cols-2 gap-3 text-sm">
        <div>
          <dt className="text-[10px] uppercase tracking-[0.12em] text-slate-600">Attack type</dt>
          <dd className="capitalize text-slate-200">{String(r.attack_type).replace(/_/g, ' ')}</dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-[0.12em] text-slate-600">MITRE tactic</dt>
          <dd className={r.mitre_tactic ? 'text-slate-200' : 'text-slate-500'}>
            {r.mitre_tactic || (r.is_malicious ? 'Not mapped' : 'Not applicable')}
          </dd>
        </div>
      </dl>

      <div>
        <p className="label">Summary</p>
        <p className="text-sm leading-relaxed text-slate-300">{r.summary}</p>
      </div>

      <div>
        <p className="label">
          Indicators of compromise <span className="text-slate-600">({r.iocs.length})</span>
        </p>
        {r.iocs.length ? (
          <div className="flex flex-wrap gap-1.5">
            {r.iocs.map((ioc) => (
              <code key={ioc} className="chip text-cyan-300">
                {ioc}
              </code>
            ))}
          </div>
        ) : (
          <p className="text-xs text-slate-600">No indicators were extracted.</p>
        )}
      </div>

      <div>
        <p className="label">
          Retrieved context <span className="text-slate-600">({result.retrieved_context.length})</span>
        </p>
        {result.retrieved_context.length === 0 ? (
          <p className="text-xs text-slate-600">No similar historical logs in the vector store yet.</p>
        ) : (
          <ul className="max-h-40 space-y-1 overflow-y-auto pr-1">
            {result.retrieved_context.map((doc, idx) => (
              <li
                key={idx}
                className="truncate rounded border border-slate-800 bg-slate-900/60 px-2 py-1 font-mono text-[11px] text-slate-500"
                title={doc}
              >
                {doc}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
