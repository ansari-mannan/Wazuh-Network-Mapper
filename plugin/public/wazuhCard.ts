// Adds a card for this plugin to the Wazuh Overview page (Wazuh's wz-home
// app) without changing Wazuh's files: it copies one of Wazuh's own module
// cards in the configured section, so it looks the same (docs/DECISIONS.md, D7).
//
// Wazuh 4.14's Overview (overview-welcome.js) renders each section as an
// OuiCard whose beta badge holds the section name; the module cards sit in an
// OuiFlexGrid inside that card's children.
import { Observable, Subscription } from 'rxjs';
import { PLUGIN_ID, PLUGIN_NAME } from '../common';

export const WAZUH_OVERVIEW_APP = 'wz-home';
export const CARD_ID = 'vulnmapperWazuhCard';
export const CARD_DESCRIPTION = 'Map network devices, attack paths and vulnerabilities across the network.';
const GIVE_UP_MS = 10000;

export interface WazuhCardConfig {
  enabled: boolean;
  section: string;
}

export interface CardNavigation {
  navigateToApp(appId: string): unknown;
  getUrlForApp(appId: string): string;
}

const SVG_NS = 'http://www.w3.org/2000/svg';
// lucide-react's Network icon, drawn by hand: the page outside our app has no React root of ours
const NETWORK_ICON = [
  ['rect', { x: '16', y: '16', width: '6', height: '6', rx: '1' }],
  ['rect', { x: '2', y: '16', width: '6', height: '6', rx: '1' }],
  ['rect', { x: '9', y: '2', width: '6', height: '6', rx: '1' }],
  ['path', { d: 'M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3' }],
  ['path', { d: 'M12 12V8' }],
] as const;

const normalize = (text: string | null) => (text || '').replace(/\s+/g, ' ').trim().toUpperCase();

/** The grid holding the module cards of the section named `section`, or null. */
function findSectionGrid(doc: Document, section: string): Element | null {
  const wanted = normalize(section);
  for (const badge of Array.from(doc.querySelectorAll('.ouiCard__betaBadge, .euiCard__betaBadge'))) {
    if (normalize(badge.textContent) !== wanted) continue;
    const grid = badge
      .closest('.ouiCard, .euiCard')
      ?.querySelector('.ouiCard__children .ouiFlexGrid, .euiCard__children .euiFlexGrid');
    if (grid) return grid;
  }
  return null;
}

function networkIcon(doc: Document, className: string): SVGSVGElement {
  const svg = doc.createElementNS(SVG_NS, 'svg');
  const attrs: Record<string, string> = {
    class: className, viewBox: '0 0 24 24', stroke: 'currentColor', 'stroke-width': '2',
    'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', focusable: 'false',
  };
  for (const [k, v] of Object.entries(attrs)) svg.setAttribute(k, v);
  svg.style.fill = 'none'; // OUI fills icons with currentColor; this one is drawn with strokes
  for (const [tag, shape] of NETWORK_ICON) {
    const el = doc.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(shape)) el.setAttribute(k, v);
    svg.appendChild(el);
  }
  return svg as SVGSVGElement;
}

/**
 * Adds our card at the end of the section's grid unless it is already on the
 * page. True when the card is there afterwards; false (nothing changed) when
 * the section or a usable card to copy is missing.
 */
export function insertCard(doc: Document, section: string, nav: CardNavigation): boolean {
  if (doc.getElementById(CARD_ID)) return true;
  const grid = findSectionGrid(doc, section);
  const template = grid && Array.from(grid.children).find((c) => c.querySelector('.ouiCard, .euiCard'));
  if (!grid || !template) return false;

  const card = template.cloneNode(true) as HTMLElement;
  const title = card.querySelector('.ouiCard__title, .euiCard__title');
  const description = card.querySelector('.ouiCard__description, .euiCard__description');
  if (!title || !description) return false;

  // cloneNode copies no listeners (React's live on its root anyway); drop what would
  // clash with or point back at the original card
  for (const el of [card, ...Array.from(card.querySelectorAll('*'))]) {
    for (const { name } of Array.from(el.attributes)) {
      if (/^(id|data-test-subj|aria-describedby|aria-labelledby|href|on.*)$/i.test(name)) el.removeAttribute(name);
    }
  }
  card.id = CARD_ID;
  card.setAttribute('data-test-subj', CARD_ID);

  const icon = card.querySelector('.ouiCard__icon, .euiCard__icon');
  icon?.replaceWith(networkIcon(doc, icon.getAttribute('class') || ''));

  const link = (title.querySelector('a, button') as HTMLElement | null) || (title as HTMLElement);
  link.textContent = PLUGIN_NAME;
  (description.querySelector('p') || description).textContent = CARD_DESCRIPTION;
  if (link.tagName === 'A') {
    link.setAttribute('href', nav.getUrlForApp(PLUGIN_ID));
  } else {
    link.setAttribute('role', 'link');
    link.tabIndex = 0;
  }
  link.setAttribute('aria-label', `${PLUGIN_NAME}: ${CARD_DESCRIPTION}`);

  const open = (e: Event) => {
    e.preventDefault();
    e.stopPropagation();
    nav.navigateToApp(PLUGIN_ID);
  };
  card.addEventListener('click', (e) => {
    if (!(e.ctrlKey || e.metaKey || e.shiftKey || e.altKey)) open(e); // modified clicks open the href in a new tab
  });
  link.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') open(e);
  });

  grid.appendChild(card); // last, after every React-managed sibling
  return true;
}

/** Watches the page while it is Wazuh's Overview and keeps one card in the section. */
function watchPage(doc: Document, section: string, nav: CardNavigation): () => void {
  let found = false;
  const ensure = () => {
    try {
      found = insertCard(doc, section, nav) || found;
    } catch (e) {
      // never break Wazuh's page over our card
    }
  };
  const observer = new MutationObserver(ensure);
  observer.observe(doc.body, { childList: true, subtree: true });
  const timer = setTimeout(() => {
    if (found) return;
    observer.disconnect();
    // eslint-disable-next-line no-console
    console.debug(`vulnmapper: no "${section}" section with a card to copy on the Wazuh Overview; no card added`);
  }, GIVE_UP_MS);
  ensure();
  return () => {
    clearTimeout(timer);
    observer.disconnect();
  };
}

/** Adds the card whenever the current app is Wazuh's Overview; unsubscribe to stop. */
export function watchWazuhOverview(
  currentAppId$: Observable<string | undefined>,
  nav: CardNavigation,
  config: WazuhCardConfig,
  doc: Document = document
): Subscription {
  if (!config.enabled) return new Subscription();
  let stop = () => {};
  const sub = currentAppId$.subscribe((appId) => {
    stop();
    stop = appId === WAZUH_OVERVIEW_APP ? watchPage(doc, config.section, nav) : () => {};
  });
  sub.add(() => stop());
  return sub;
}
