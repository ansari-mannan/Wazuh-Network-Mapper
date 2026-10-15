// Colours and dark-mode detection for what is drawn from code (map, charts).
import { darkMode, euiThemeVars } from '@osd/ui-shared-deps/theme';
import type { Tier } from './riskRule';

// The dashboard's dark mode setting (theme:darkMode), as resolved by the server
// when it rendered this page (it also honours a YAML override or ?themeTag=).
// This is the same value that selected the compiled light/dark stylesheet, so
// inline colours set from JS always agree with the SCSS. Changing the setting
// reloads the page, so reading it once is enough.
export const isDarkMode = Boolean(darkMode);

// OUI theme variables for the active theme (text, borders, backgrounds).
export const themeVars = euiThemeVars;

const LIGHT = {
  // colours used inside the graph canvas that have no OUI equivalent
  graph: {
    edgeLldp: '#475569',
    edgeEndpoint: '#64748b',
    edgeFdb: '#94a3b8',
    edgeWifi: '#0d9488',
    edgeInferred: '#f59e0b',
    labelInferred: '#b45309',
    // the attack route (map, faceplate, selected route card): OUI's danger red.
    // P0 is also red, so the route is told apart by its glow and moving dashes.
    route: '#BD271E',
    // the step number written on the route colour
    routeText: '#ffffff',
  },
  // an OVSS tier's colour when it is text (lib/risk colours are for fills and
  // borders; yellow on a light page is too faint to read)
  tierText: { P0: '#b91c1c', P1: '#c2410c', P2: '#a16207', P3: '#1d4ed8' } as Record<Tier, string>,
};

const DARK: typeof LIGHT = {
  graph: {
    edgeLldp: '#a3b1c6',
    edgeEndpoint: '#8494ab',
    edgeFdb: '#66758c',
    edgeWifi: '#2dd4bf',
    edgeInferred: '#f59e0b',
    labelInferred: '#fbbf24',
    route: '#FF6666',
    routeText: '#1d1e24',
  },
  tierText: { P0: '#f87171', P1: '#fb923c', P2: '#facc15', P3: '#60a5fa' },
};

/** The plugin's own colours for a dark or a light dashboard. */
export const paletteFor = (dark: boolean) => (dark ? DARK : LIGHT);

const palette = paletteFor(isDarkMode);
export const graphColors = palette.graph;
export const tierTextColors = palette.tierText;
