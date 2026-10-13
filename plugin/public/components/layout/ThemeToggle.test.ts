/**
 * @jest-environment jsdom
 */
import { toggleDarkMode } from './ThemeToggle';

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

  it('shows a toast and stays on the page when the save is refused', async () => {
    const s = setup(false, jest.fn(async () => false));
    await toggleDarkMode(s.uiSettings, s.notifications, s.reload);
    expect(s.reload).not.toHaveBeenCalled();
    expect(s.notifications.toasts.addWarning).toHaveBeenCalled();
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
