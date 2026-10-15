import fs from 'fs';
import path from 'path';
import { paletteFor } from './theme';

describe('theme palette', () => {
  it('gives the dark palette on a dark dashboard and the light one otherwise', () => {
    expect(paletteFor(true).graph.route).toBe('#FF6666');
    expect(paletteFor(false).graph.route).toBe('#BD271E');
    expect(paletteFor(true).tierText.P2).not.toBe(paletteFor(false).tierText.P2);
  });

  it('follows the theme the dashboard rendered', () => {
    for (const darkMode of [true, false]) {
      jest.isolateModules(() => {
        jest.doMock('@osd/ui-shared-deps/theme', () => ({ darkMode, euiThemeVars: {} }));
        const theme = require('./theme');
        expect(theme.isDarkMode).toBe(darkMode);
        expect(theme.graphColors.route).toBe(darkMode ? '#FF6666' : '#BD271E');
        expect(theme.graphColors).toBe(theme.paletteFor(darkMode).graph);
        expect(theme.tierTextColors).toBe(theme.paletteFor(darkMode).tierText);
      });
    }
  });
});

describe('route colour', () => {
  it('leaves no old violet route colour in the plugin', () => {
    const left: string[] = [];
    const walk = (dir: string) => {
      for (const f of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, f.name);
        if (f.isDirectory()) walk(p);
        else if (/#(7c3aed|a78bfa|b79cff)\b|violet/i.test(fs.readFileSync(p, 'utf8'))) left.push(p);
      }
    };
    walk(path.join(__dirname, '..'));
    expect(left.filter((p) => p !== __filename)).toEqual([]);
  });
});
