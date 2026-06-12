import { useMemo, useState } from 'react';
import {
  ComposableMap,
  Geographies,
  Geography,
  ZoomableGroup,
} from 'react-simple-maps';

const GEO_URL = '/world-110m.json';

// Backend country label -> world-atlas country name
const NAME_ALIAS: Record<string, string> = {
  'United States': 'United States of America',
  'Czech Republic': 'Czechia',
  'Russia': 'Russia',
  'South Korea': 'South Korea',
};

const SKIP = new Set(['Global', 'Other / Unknown', 'Unknown']);

export interface MapRow {
  country: string;
  value: number;
  kev: number;
}

interface Props {
  data: MapRow[];
  height?: number;
}

function hexToRgb(hex: string): [number, number, number] {
  const n = parseInt(hex.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

function lerp(a: number, b: number, t: number) {
  return Math.round(a + (b - a) * t);
}

// cool -> violet -> magenta -> hot red ramp
const STOPS = ['#13234d', '#3b3a8c', '#7c5cff', '#c13aa6', '#ff4d6d'];

function rampColor(t: number): string {
  const clamped = Math.max(0, Math.min(1, t));
  const seg = clamped * (STOPS.length - 1);
  const i = Math.min(STOPS.length - 2, Math.floor(seg));
  const local = seg - i;
  const [r1, g1, b1] = hexToRgb(STOPS[i]);
  const [r2, g2, b2] = hexToRgb(STOPS[i + 1]);
  return `rgb(${lerp(r1, r2, local)}, ${lerp(g1, g2, local)}, ${lerp(b1, b2, local)})`;
}

export function WorldMap({ data, height = 460 }: Props) {
  const [tip, setTip] = useState<{ x: number; y: number; html: string } | null>(null);

  const { lookup, max } = useMemo(() => {
    const map = new Map<string, MapRow>();
    let m = 0;
    for (const row of data) {
      if (SKIP.has(row.country)) continue;
      const name = NAME_ALIAS[row.country] || row.country;
      map.set(name, row);
      if (row.value > m) m = row.value;
    }
    return { lookup: map, max: m || 1 };
  }, [data]);

  return (
    <div className="worldmap-wrap" style={{ height }}>
      <ComposableMap
        projection="geoEqualEarth"
        projectionConfig={{ scale: 165 }}
        style={{ width: '100%', height: '100%' }}
      >
        <ZoomableGroup zoom={1} minZoom={1} maxZoom={5} center={[15, 10]}>
          <Geographies geography={GEO_URL}>
            {({ geographies }: { geographies: any[] }) =>
              geographies.map((geo) => {
                const name = geo.properties.name as string;
                const row = lookup.get(name);
                const value = row?.value ?? 0;
                // sqrt scaling so smaller counts are still visible
                const t = value ? Math.sqrt(value / max) : 0;
                const fill = value ? rampColor(t) : 'rgba(120, 130, 180, 0.10)';
                return (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    fill={fill}
                    stroke="rgba(10, 12, 30, 0.85)"
                    strokeWidth={0.4}
                    style={{
                      default: { outline: 'none', transition: 'fill 0.3s ease' },
                      hover: {
                        outline: 'none',
                        fill: value ? '#00f5d4' : 'rgba(0, 245, 212, 0.25)',
                        cursor: value ? 'pointer' : 'default',
                      },
                      pressed: { outline: 'none' },
                    }}
                    onMouseEnter={(e) => {
                      setTip({
                        x: e.clientX,
                        y: e.clientY,
                        html: row
                          ? `<strong>${row.country}</strong><br/>${value.toLocaleString()} vulnerabilities${
                              row.kev ? `<br/>${row.kev} actively exploited` : ''
                            }`
                          : `<strong>${name}</strong><br/>no tracked vendors`,
                      });
                    }}
                    onMouseMove={(e) =>
                      setTip((prev) => (prev ? { ...prev, x: e.clientX, y: e.clientY } : prev))
                    }
                    onMouseLeave={() => setTip(null)}
                  />
                );
              })
            }
          </Geographies>
        </ZoomableGroup>
      </ComposableMap>

      <div className="worldmap-legend">
        <span className="worldmap-legend-label">Low</span>
        <div className="worldmap-legend-bar" />
        <span className="worldmap-legend-label">High</span>
      </div>

      {tip && (
        <div
          className="worldmap-tip"
          style={{ left: tip.x + 14, top: tip.y + 14 }}
          dangerouslySetInnerHTML={{ __html: tip.html }}
        />
      )}
    </div>
  );
}
