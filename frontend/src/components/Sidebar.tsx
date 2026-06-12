import { type ReactElement, type ReactNode } from 'react';

export interface NavSection {
  id: string;
  label: string;
  icon: ReactElement;
}

const ic = (path: ReactNode) => (
  <svg
    viewBox="0 0 24 24"
    width="20"
    height="20"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    {path}
  </svg>
);

export const NAV_SECTIONS: NavSection[] = [
  {
    id: 'sec-overview',
    label: 'Overview',
    icon: ic(
      <>
        <rect x="3" y="3" width="7" height="7" />
        <rect x="14" y="3" width="7" height="7" />
        <rect x="3" y="14" width="7" height="7" />
        <rect x="14" y="14" width="7" height="7" />
      </>
    ),
  },
  {
    id: 'sec-live',
    label: 'Live feed',
    icon: ic(
      <>
        <path d="M2 12h4l3 8 4-16 3 8h6" />
      </>
    ),
  },
  {
    id: 'sec-threats',
    label: 'Threat analysis',
    icon: ic(
      <>
        <path d="M12 2 4 5v6c0 5 3.5 8 8 11 4.5-3 8-6 8-11V5l-8-3z" />
        <path d="M12 8v4" />
        <path d="M12 16h.01" />
      </>
    ),
  },
  {
    id: 'sec-geo',
    label: 'Geographic',
    icon: ic(
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18" />
      </>
    ),
  },
  {
    id: 'sec-industries',
    label: 'Industries',
    icon: ic(
      <>
        <path d="M3 21h18M5 21V10l5 3V7l5 3V5l4 2v14" />
      </>
    ),
  },
  {
    id: 'sec-sectors',
    label: 'Org sectors',
    icon: ic(
      <>
        <rect x="3" y="9" width="18" height="12" rx="1" />
        <path d="M8 9V5a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v4" />
      </>
    ),
  },
  {
    id: 'sec-vendors',
    label: 'Vendors',
    icon: ic(
      <>
        <path d="M3 7h18l-1.5 13H4.5L3 7z" />
        <path d="M8 7V5a4 4 0 0 1 8 0v2" />
      </>
    ),
  },
  {
    id: 'sec-exploits',
    label: 'Confirmed exploits',
    icon: ic(
      <>
        <path d="m13 2-9 12h7l-1 8 9-12h-7l1-8z" />
      </>
    ),
  },
];

interface SidebarProps {
  active: string;
  onNavigate: (id: string) => void;
}

export function Sidebar({ active, onNavigate }: SidebarProps) {
  return (
    <aside className="sidebar">
      <div className="sidebar-inner">
        <div className="sidebar-brand">
          <img className="sidebar-brand-mark" src="/vulnify.svg" alt="Vulnify" width="32" height="32" />
        </div>
        <nav className="sidebar-nav">
          {NAV_SECTIONS.map((s) => (
            <button
              key={s.id}
              type="button"
              className={`sidebar-link${active === s.id ? ' active' : ''}`}
              onClick={() => onNavigate(s.id)}
            >
              <span className="sidebar-icon">{s.icon}</span>
              <span className="sidebar-label">{s.label}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <span className="sidebar-icon">
            {ic(
              <>
                <circle cx="12" cy="12" r="9" />
                <path d="M12 8v4l3 2" />
              </>
            )}
          </span>
          <span className="sidebar-label">Live · real feeds</span>
        </div>
      </div>
    </aside>
  );
}
