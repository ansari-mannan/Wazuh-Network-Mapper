import { darkMode, euiThemeVars } from '@osd/ui-shared-deps/theme';

// The dashboard's dark mode setting (theme:darkMode), as resolved by the server
// when it rendered this page (it also honours a YAML override or ?themeTag=).
// This is the same value that selected the compiled light/dark stylesheet, so
// inline colours set from JS always agree with the SCSS. Changing the setting
// reloads the page, so reading it once is enough.
export const isDarkMode = Boolean(darkMode);

// OUI theme variables for the active theme (text, borders, backgrounds).
export const themeVars = euiThemeVars;

// Colours used inside the graph canvas that have no OUI equivalent.
export const graphColors = isDarkMode
  ? {
      edgeLldp: '#a3b1c6',
      edgeEndpoint: '#8494ab',
      edgeFdb: '#66758c',
      edgeInferred: '#f59e0b',
      labelInferred: '#fbbf24',
    }
  : {
      edgeLldp: '#475569',
      edgeEndpoint: '#64748b',
      edgeFdb: '#94a3b8',
      edgeInferred: '#f59e0b',
      labelInferred: '#b45309',
    };
