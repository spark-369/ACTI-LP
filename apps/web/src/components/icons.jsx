/**
 * Inline SVG icon set (stroke-based, currentColor). No icon dependency added.
 * Every icon accepts className; default 16px inherited from `size`.
 */
const base = (size) => ({
  width: size,
  height: size,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.8,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
  'aria-hidden': true,
});

export const Icon = {
  Shield: ({ size = 16, className = '' }) => (
    <svg {...base(size)} className={className}>
      <path d="M12 3 4.5 6v6c0 4.5 3.2 7.9 7.5 9 4.3-1.1 7.5-4.5 7.5-9V6L12 3Z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  ),
  Dashboard: ({ size = 16, className = '' }) => (
    <svg {...base(size)} className={className}>
      <rect x="3" y="3" width="7" height="9" rx="1.5" />
      <rect x="14" y="3" width="7" height="5" rx="1.5" />
      <rect x="14" y="12" width="7" height="9" rx="1.5" />
      <rect x="3" y="16" width="7" height="5" rx="1.5" />
    </svg>
  ),
  Alert: ({ size = 16, className = '' }) => (
    <svg {...base(size)} className={className}>
      <path d="M10.3 4.3 2.8 17a2 2 0 0 0 1.7 3h15a2 2 0 0 0 1.7-3L13.7 4.3a2 2 0 0 0-3.4 0Z" />
      <path d="M12 9v4" />
      <path d="M12 17h.01" />
    </svg>
  ),
  Terminal: ({ size = 16, className = '' }) => (
    <svg {...base(size)} className={className}>
      <rect x="2.5" y="4" width="19" height="16" rx="2" />
      <path d="m6.5 9 3 3-3 3" />
      <path d="M12.5 15h5" />
    </svg>
  ),
  Users: ({ size = 16, className = '' }) => (
    <svg {...base(size)} className={className}>
      <circle cx="9" cy="8" r="3.2" />
      <path d="M2.8 20a6.2 6.2 0 0 1 12.4 0" />
      <path d="M16.5 5.2a3.2 3.2 0 0 1 0 5.6" />
      <path d="M18 20a6.2 6.2 0 0 0-2-4.5" />
    </svg>
  ),
  Audit: ({ size = 16, className = '' }) => (
    <svg {...base(size)} className={className}>
      <path d="M4 3.5h9l5 5V20a1.5 1.5 0 0 1-1.5 1.5h-12A1.5 1.5 0 0 1 3 20V5a1.5 1.5 0 0 1 1-1.5Z" />
      <path d="M13 3.5v5h5" />
      <path d="M7 13h7" />
      <path d="M7 17h4" />
    </svg>
  ),
  Search: ({ size = 16, className = '' }) => (
    <svg {...base(size)} className={className}>
      <circle cx="11" cy="11" r="6.5" />
      <path d="m16 16 4.5 4.5" />
    </svg>
  ),
  Refresh: ({ size = 16, className = '' }) => (
    <svg {...base(size)} className={className}>
      <path d="M20 11a8 8 0 1 0-2.3 6.3" />
      <path d="M20 4.5V11h-6.2" />
    </svg>
  ),
  Close: ({ size = 16, className = '' }) => (
    <svg {...base(size)} className={className}>
      <path d="m6 6 12 12M18 6 6 18" />
    </svg>
  ),
  ChevronRight: ({ size = 16, className = '' }) => (
    <svg {...base(size)} className={className}>
      <path d="m9 6 6 6-6 6" />
    </svg>
  ),
  ChevronDown: ({ size = 16, className = '' }) => (
    <svg {...base(size)} className={className}>
      <path d="m6 9 6 6 6-6" />
    </svg>
  ),
  Check: ({ size = 16, className = '' }) => (
    <svg {...base(size)} className={className}>
      <path d="m4.5 12.5 5 5 10-11" />
    </svg>
  ),
  Play: ({ size = 16, className = '' }) => (
    <svg {...base(size)} className={className}>
      <path d="M7 4.5v15l12-7.5-12-7.5Z" />
    </svg>
  ),
  Logout: ({ size = 16, className = '' }) => (
    <svg {...base(size)} className={className}>
      <path d="M15 4.5h3.5A1.5 1.5 0 0 1 20 6v12a1.5 1.5 0 0 1-1.5 1.5H15" />
      <path d="M11 8 7 12l4 4" />
      <path d="M7 12h9" />
    </svg>
  ),
  Cpu: ({ size = 16, className = '' }) => (
    <svg {...base(size)} className={className}>
      <rect x="7" y="7" width="10" height="10" rx="2" />
      <path d="M10 2.5v3M14 2.5v3M10 18.5v3M14 18.5v3M2.5 10h3M2.5 14h3M18.5 10h3M18.5 14h3" />
    </svg>
  ),
  Database: ({ size = 16, className = '' }) => (
    <svg {...base(size)} className={className}>
      <ellipse cx="12" cy="5.5" rx="7.5" ry="3" />
      <path d="M4.5 5.5v13c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3v-13" />
      <path d="M4.5 12c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3" />
    </svg>
  ),
  Plus: ({ size = 16, className = '' }) => (
    <svg {...base(size)} className={className}>
      <path d="M12 5v14M5 12h14" />
    </svg>
  ),
  Filter: ({ size = 16, className = '' }) => (
    <svg {...base(size)} className={className}>
      <path d="M3 5.5h18l-7 8v6l-4 2v-8l-7-8Z" />
    </svg>
  ),
  Inbox: ({ size = 16, className = '' }) => (
    <svg {...base(size)} className={className}>
      <path d="M3 13.5 5.5 5h13L21 13.5V19a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 19v-5.5Z" />
      <path d="M3 13.5h4l1.5 3h7l1.5-3h4" />
    </svg>
  ),
};

export default Icon;
