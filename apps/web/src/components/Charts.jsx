import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

const SEV_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

const tooltipStyle = {
  backgroundColor: '#0f172a',
  border: '1px solid #1e293b',
  borderRadius: 8,
  color: '#e2e8f0',
  fontSize: 12,
};

// Recharts sets its own colours for the tooltip *label* and *item text*, which
// override `tooltipStyle.color` and default to near-black — invisible on the
// dark panel. These are applied per element instead.
const tooltipLabelStyle = { color: '#f1f5f9', fontWeight: 600, marginBottom: 4 };
const tooltipItemStyle = { color: '#e2e8f0' };

// Legend text is likewise coloured by Recharts (default #000). Style the wrapper
// and its list items explicitly so labels are readable on the dark surface.
const legendStyle = {
  fontSize: 12,
  color: '#cbd5e1',
  paddingTop: 4,
};

/**
 * Custom tooltip.
 *
 * Recharts' built-in Tooltip renders the label and item names with its own
 * hardcoded colours, so setting `contentStyle.color` styles the panel but leaves
 * the text near-black on a dark background. Rendering the content ourselves is
 * the only reliable way to control every text node.
 */
function DarkTooltip({ active, payload, label, formatter, labelFormatter }) {
  if (!active || !payload || !payload.length) return null;

  const heading = labelFormatter ? labelFormatter(label, payload) : label;

  return (
    <div style={tooltipStyle}>
      {heading != null && heading !== '' && <div style={tooltipLabelStyle}>{heading}</div>}
      {payload.map((entry, index) => {
        const [value, name] = formatter
          ? formatter(entry.value, entry.name, entry, index, payload)
          : [entry.value, entry.name];
        return (
          <div
            key={`${entry.dataKey || entry.name}-${index}`}
            style={{ ...tooltipItemStyle, display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <span
              style={{
                width: 8,
                height: 8,
                borderRadius: 2,
                backgroundColor: entry.payload?.fill || entry.color || '#64748b',
                flexShrink: 0,
              }}
            />
            {name != null && name !== '' && <span>{name}</span>}
            <span style={{ marginLeft: 'auto', fontWeight: 600 }}>{value}</span>
          </div>
        );
      })}
    </div>
  );
}

export function SeverityChart({ data }) {
  // Recharts renders a slice *and* a label for count: 0, so four severities with
  // only one populated produced overlapping labels ("critical: 0" / "medium").
  // Zero-value severities carry no information in a donut — drop them and let
  // the legend + tooltip convey the rest.
  const slices = (data || []).filter((d) => Number(d.count) > 0);
  const total = slices.reduce((sum, d) => sum + Number(d.count), 0);

  if (!slices.length) {
    return (
      <div className="grid h-[240px] place-items-center text-xs text-slate-500">No alerts yet</div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={240}>
      <PieChart margin={{ top: 0, right: 0, bottom: 0, left: 0 }}>
        <Pie
          data={slices}
          dataKey="count"
          nameKey="severity"
          innerRadius={52}
          outerRadius={78}
          paddingAngle={2}
          labelLine={false}
        >
          {slices.map((entry) => (
            <Cell key={entry.severity} fill={SEV_COLORS[entry.severity] || '#64748b'} />
          ))}
        </Pie>
        <Tooltip
          content={<DarkTooltip formatter={(value, name) => [`${value} (${Math.round((value / total) * 100)}%)`, name]} />}
        />
        {/* Recharts colours legend text from each series' fill; for a Pie with
            per-Cell fills it falls back to black. Force the readable colour. */}
        <Legend
          wrapperStyle={legendStyle}
          formatter={(value) => <span style={{ color: '#cbd5e1' }}>{value}</span>}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}

export function TimelineChart({ data }) {
  return (
    <ResponsiveContainer width="100%" height={240}>
      <LineChart data={data} margin={{ top: 8, right: 16, bottom: 0, left: -16 }}>
        <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
        <XAxis dataKey="date" stroke="#64748b" fontSize={11} />
        <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
        <Tooltip content={<DarkTooltip />} />
        <Line type="monotone" dataKey="count" stroke="#22d3ee" strokeWidth={2} dot={false} />
      </LineChart>
    </ResponsiveContainer>
  );
}

export function AttackTypeChart({ data }) {
  const rows = (data || []).slice(0, 8).map((d) => ({
    ...d,
    label: String(d.attack_type || '').replace(/_/g, ' '),
  }));

  if (!rows.length) {
    return (
      <div className="grid h-[260px] place-items-center text-xs text-slate-500">
        No malicious activity yet
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 24, bottom: 4, left: 8 }}>
        <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" horizontal={false} />
        <XAxis type="number" stroke="#64748b" fontSize={11} allowDecimals={false} />
        <YAxis
          type="category"
          dataKey="label"
          stroke="#64748b"
          fontSize={11}
          width={140}
          interval={0}
          tickFormatter={(value) => (value.length > 20 ? `${value.slice(0, 19)}…` : value)}
        />
        <Tooltip content={<DarkTooltip />} />
        <Bar dataKey="count" fill="#38bdf8" radius={[0, 6, 6, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
