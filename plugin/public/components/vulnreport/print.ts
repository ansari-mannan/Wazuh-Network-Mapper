// Printing the report so the browser offers the report's own name for the PDF.
// The save dialog takes the file name from the tab title, which the dashboard's
// chrome.docTitle service owns. Some browsers return from window.print() before
// the dialog reads the title, so the page title comes back only on "afterprint".

interface DocTitle {
  change: (title: string | string[]) => void;
}

/** "ntm-apa-mapper-vuln-report-2026-10-08": the PDF's file name, without extension. */
export const reportFileName = (date: string) => `ntm-apa-mapper-vuln-report-${date}`;

/**
 * Show ``name`` as the tab title, print once it is applied, then give the page
 * back ``restoreTitle``. ``done`` resolves when the title is restored;
 * ``cancel`` restores it at once (the page unmounted mid-print).
 */
export function printWithTitle(
  docTitle: DocTitle,
  name: string,
  restoreTitle: string[],
  win: Window = window
): { done: Promise<void>; cancel: () => void } {
  let finished = false;
  let resolve: () => void = () => {};
  const done = new Promise<void>((r) => (resolve = r));
  const finish = () => {
    if (finished) return;
    finished = true;
    win.removeEventListener('afterprint', finish);
    docTitle.change(restoreTitle);
    resolve();
  };

  docTitle.change([name]);
  // The service appends the dashboard's own name ("... - Wazuh"); the file
  // name is the report's alone.
  win.document.title = name;
  win.addEventListener('afterprint', finish);
  win.requestAnimationFrame(() => {
    if (finished) return;
    try {
      win.print();
    } catch (e) {
      finish();
    }
  });
  return { done, cancel: finish };
}
