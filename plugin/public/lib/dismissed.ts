// Notes the user has dismissed, remembered in this browser only. Storage can
// be missing or throw (private mode, blocked site data), so every access is
// guarded and a failure just shows the note again.
const PREFIX = 'vulnmapper.dismissed.';

type Store = Pick<Storage, 'getItem' | 'setItem'>;

function store(): Store | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

export function isDismissed(key: string, storage: Store | null = store()): boolean {
  try {
    return storage?.getItem(PREFIX + key) === '1';
  } catch {
    return false;
  }
}

export function rememberDismissed(key: string, storage: Store | null = store()): void {
  try {
    storage?.setItem(PREFIX + key, '1');
  } catch {
    // not remembered: the note comes back next time
  }
}
