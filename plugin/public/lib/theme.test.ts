import { paletteFor } from './theme';

describe('theme palette', () => {
  it('gives the dark palette on a dark dashboard and the light one otherwise', () => {
    expect(paletteFor(true).graph.route).toBe('#a78bfa');
    expect(paletteFor(false).graph.route).toBe('#7c3aed');
    expect(paletteFor(true).tierText.P2).not.toBe(paletteFor(false).tierText.P2);
  });

  it('follows the theme the dashboard rendered', () => {
    for (const darkMode of [true, false]) {
      jest.isolateModules(() => {
        jest.doMock('@osd/ui-shared-deps/theme', () => ({ darkMode, euiThemeVars: {} }));
        const theme = require('./theme');
        expect(theme.isDarkMode).toBe(darkMode);
        expect(theme.graphColors.route).toBe(darkMode ? '#a78bfa' : '#7c3aed');
        expect(theme.graphColors).toBe(theme.paletteFor(darkMode).graph);
        expect(theme.tierTextColors).toBe(theme.paletteFor(darkMode).tierText);
      });
    }
  });
});
