// Sun/moon button in every page header: flips the dashboard's own dark mode
// setting and reloads, since the compiled stylesheet is picked at page load.
import React from 'react';
import { EuiButtonIcon, EuiToolTip } from '@elastic/eui';
import { CoreStart } from '../../../../../src/core/public';
import { useServices } from '../../lib/services';

const SETTING = 'theme:darkMode';

// OUI 1.x has a moon icon but no sun.
function SunIcon(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 16 16" width={16} height={16} fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" {...props}>
      <circle cx="8" cy="8" r="3" />
      <path d="M8 1v1.5M8 13.5V15M1 8h1.5M13.5 8H15M3 3l1 1M12 12l1 1M3 13l1-1M12 4l1-1" />
    </svg>
  );
}

/**
 * Save the flipped setting and reload. theme:darkMode is a global setting in
 * OpenSearch Dashboards 2.19 (it declares no user scope), so this changes it
 * for everyone. A setting fixed in opensearch_dashboards.yml makes set() throw;
 * a refused save (no permission, read-only) makes it return false.
 */
export async function toggleDarkMode(
  uiSettings: Pick<CoreStart['uiSettings'], 'get' | 'set'>,
  notifications: CoreStart['notifications'],
  reload: () => void = () => window.location.reload()
) {
  let saved = false;
  try {
    saved = await uiSettings.set(SETTING, !uiSettings.get(SETTING));
  } catch {
    saved = false;
  }
  if (saved) return reload();
  notifications.toasts.addWarning({
    title: 'Could not change the theme',
    text:
      'The dashboard did not accept the dark mode change: it may be fixed in the server ' +
      'configuration, or your account may not be allowed to change Advanced settings.',
  });
}

export function ThemeToggle() {
  const { uiSettings, notifications } = useServices();
  const dark = Boolean(uiSettings.get(SETTING));
  const label = dark ? 'Switch to light mode' : 'Switch to dark mode';
  return (
    <EuiToolTip content={label}>
      <EuiButtonIcon
        iconType={dark ? SunIcon : 'moon'}
        aria-label={label}
        onClick={() => toggleDarkMode(uiSettings, notifications)}
        data-test-subj="vmThemeToggle"
      />
    </EuiToolTip>
  );
}
