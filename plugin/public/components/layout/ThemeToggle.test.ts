/**
 * @jest-environment jsdom
 */
// Each test loads the module afresh: a switch that reloads keeps further clicks out.
let toggleDarkMode: typeof import('./ThemeToggle').toggleDarkMode;
beforeEach(() => {
  jest.resetModules();
  ({ toggleDarkMode } = require('./ThemeToggle'));
});

function setup(dark: boolean, set: jest.Mock) {
  const uiSettings = { get: jest.fn(() => dark), set } as any;
  const notifications = { toasts: { addWarning: jest.fn() } } as any;
  const reload = jest.fn();
  return { uiSettings, notifications, reload };
}

describe('toggleDarkMode', () => {
  it('saves the flipped setting and reloads', async () => {
    const s = setup(false, jest.fn(async () => true));
    await toggleDarkMode(s.uiSettings, s.notifications, s.reload);
    expect(s.uiSettings.set).toHaveBeenCalledWith('theme:darkMode', true);
    expect(s.reload).toHaveBeenCalled();
    expect(s.notifications.toasts.addWarning).not.toHaveBeenCalled();
  });

  it('turns dark mode off when it is on', async () => {
    const s = setup(true, jest.fn(async () => true));
    await toggleDarkMode(s.uiSettings, s.notifications, s.reload);
    expect(s.uiSettings.set).toHaveBeenCalledWith('theme:darkMode', false);
  });

  it('saves and reloads once however often it is clicked', async () => {
    let finish: (ok: boolean) => void = () => undefined;
    const s = setup(false, jest.fn(() => new Promise<boolean>((r) => (finish = r))));
    const first = toggleDarkMode(s.uiSettings, s.notifications, s.reload);
    await toggleDarkMode(s.uiSettings, s.notifications, s.reload); // a second click while saving
    finish(true);
    await first;
    await toggleDarkMode(s.uiSettings, s.notifications, s.reload); // and one before the reload lands
    expect(s.uiSettings.set).toHaveBeenCalledTimes(1);
    expect(s.reload).toHaveBeenCalledTimes(1);
  });

  it('shows a toast and stays on the page when the save is refused', async () => {
    const s = setup(false, jest.fn(async () => false));
    await toggleDarkMode(s.uiSettings, s.notifications, s.reload);
    expect(s.reload).not.toHaveBeenCalled();
    expect(s.notifications.toasts.addWarning).toHaveBeenCalled();
    await toggleDarkMode(s.uiSettings, s.notifications, s.reload); // and can be tried again
    expect(s.uiSettings.set).toHaveBeenCalledTimes(2);
  });

  it('shows a toast when the setting is fixed by the server', async () => {
    const s = setup(false, jest.fn(async () => {
      throw new Error('overridden');
    }));
    await toggleDarkMode(s.uiSettings, s.notifications, s.reload);
    expect(s.reload).not.toHaveBeenCalled();
    expect(s.notifications.toasts.addWarning).toHaveBeenCalled();
  });
});
