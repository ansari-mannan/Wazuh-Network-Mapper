// Colours and dark-mode detection for what is drawn from code (map, charts).
import { darkMode, euiThemeVars } from '@osd/ui-shared-deps/theme';
import type { RiskLevel } from './riskRule';

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
    // the route on "Show on map": a colour no risk band uses
    route: '#7c3aed',
    // the step number written on the route colour
    routeText: '#ffffff',
  },
  // a risk band's colour when it is text (lib/risk colours are for fills and
  // borders; yellow and green on a light page are too faint to read)
  riskText: {
    critical: '#b91c1c',
    high: '#c2410c',
    medium: '#a16207',
    low: '#15803d',
    unscored: '#69707d',
  } as Record<RiskLevel, string>,
};

const DARK: typeof LIGHT = {
  graph: {
    edgeLldp: '#a3b1c6',
    edgeEndpoint: '#8494ab',
    edgeFdb: '#66758c',
    edgeWifi: '#2dd4bf',
    edgeInferred: '#f59e0b',
    labelInferred: '#fbbf24',
    route: '#a78bfa',
    routeText: '#1d1e24',
  },
  riskText: { critical: '#f87171', high: '#fb923c', medium: '#facc15', low: '#4ade80', unscored: '#98a2b3' },
};

/** The plugin's own colours for a dark or a light dashboard. */
export const paletteFor = (dark: boolean) => (dark ? DARK : LIGHT);

const palette = paletteFor(isDarkMode);
export const graphColors = palette.graph;
export const riskTextColors = palette.riskText;
