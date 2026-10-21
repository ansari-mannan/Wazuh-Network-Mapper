/**
 * @jest-environment jsdom
 */
// The Wazuh Overview card, on a copy of the markup Wazuh 4.14's
// overview-welcome.js renders (OuiCard sections, the name in the beta badge).
import { BehaviorSubject } from 'rxjs';
import { CARD_DESCRIPTION, CARD_ID, insertCard, watchWazuhOverview } from './wazuhCard';

const moduleCard = (id: string, title: string) => `
  <div class="ouiFlexItem ouiFlexItem--flexGrowZero">
    <div class="h-100">
      <div class="ouiPanel ouiCard ouiCard--horizontal ouiCard--isClickable wz-module-card-title h-100" data-test-subj="overviewWelcome${id}">
        <div class="ouiCard__top"><svg class="ouiIcon ouiIcon--xLarge ouiCard__icon" id="icon-${id}"></svg></div>
        <div class="ouiCard__content">
          <span class="ouiTitle ouiTitle--xsmall ouiCard__title" id="t-${id}"><span>
            <a class="ouiCard__titleAnchor" href="/app/${id}" aria-describedby="d-${id}" onclick="alert(1)">${title}</a>
          </span></span>
          <div class="ouiText ouiCard__description" id="d-${id}"><p>${title} description</p></div>
        </div>
      </div>
    </div>
  </div>`;

const section = (name: string, cards: string) => `
  <div class="ouiFlexItem">
    <div class="ouiPanel ouiCard ouiCard--hasBetaBadge">
      <div class="ouiCard__content">
        <span class="ouiTitle ouiCard__title"><span></span></span>
        <div class="ouiCard__children"><div class="ouiSpacer"></div>
          <div class="ouiFlexGrid ouiFlexGrid--responsive">${cards}</div>
        </div>
      </div>
      <span class="ouiCard__betaBadgeWrapper"><span class="ouiBetaBadge ouiCard__betaBadge">${name}</span></span>
    </div>
  </div>`;

const threatCards = moduleCard('Vulnerability-detection', 'Vulnerability Detection') + moduleCard('Mitre-attack', 'MITRE ATT&CK');

function renderOverview() {
  document.body.innerHTML = `<div id="app">${
    section('Endpoint security', moduleCard('Configuration-assessment', 'Configuration Assessment')) +
    section('Threat intelligence', threatCards)
  }</div>`;
}

const grid = (name: string) =>
  Array.from(document.querySelectorAll('.ouiCard__betaBadge'))
    .find((b) => b.textContent === name)!
    .closest('.ouiCard')!
    .querySelector('.ouiFlexGrid')!;

const cards = () => document.querySelectorAll(`[data-test-subj="${CARD_ID}"]`);
const flush = () => new Promise((r) => setTimeout(r, 0)); // lets MutationObserver callbacks run

function makeNav() {
  return { navigateToApp: jest.fn(), getUrlForApp: jest.fn((id: string) => `/base/app/${id}`) };
}

afterEach(() => {
  document.body.innerHTML = '';
  jest.restoreAllMocks();
});

describe('insertCard', () => {
  it('adds exactly one card, last in the configured section, with our text and test subject', () => {
    renderOverview();
    expect(insertCard(document, 'THREAT INTELLIGENCE', makeNav())).toBe(true);
    expect(cards()).toHaveLength(1);
    const threat = grid('Threat intelligence');
    expect(threat.lastElementChild).toBe(cards()[0]);
    expect(threat.children).toHaveLength(3);
    expect(grid('Endpoint security').children).toHaveLength(1);

    const card = cards()[0] as HTMLElement;
    expect(card.querySelector('.ouiCard__titleAnchor')!.textContent).toBe('Network Topology Mapper');
    expect(card.querySelector('.ouiCard__description p')!.textContent).toBe(CARD_DESCRIPTION);
    const link = card.querySelector('a')!;
    expect(link.getAttribute('href')).toBe('/base/app/vulnmapper');
    expect(link.getAttribute('aria-label')).toContain('Network Topology Mapper');
    expect(link.hasAttribute('onclick')).toBe(false);
    expect(link.hasAttribute('aria-describedby')).toBe(false);
    // nothing copied that names the original card
    expect(card.querySelectorAll('[id], [data-test-subj]')).toHaveLength(0);
    // our icon, same size classes as Wazuh's
    const icon = card.querySelector('svg')!;
    expect(icon.getAttribute('class')).toBe('ouiIcon ouiIcon--xLarge ouiCard__icon');
    expect(icon.querySelectorAll('rect')).toHaveLength(3);
  });

  it('adds it only once', () => {
    renderOverview();
    insertCard(document, 'THREAT INTELLIGENCE', makeNav());
    insertCard(document, 'threat intelligence', makeNav());
    expect(cards()).toHaveLength(1);
  });

  it('does nothing when the section or a card to copy is missing', () => {
    renderOverview();
    expect(insertCard(document, 'CLOUD SECURITY', makeNav())).toBe(false);
    document.body.innerHTML = section('Cloud security', '');
    expect(insertCard(document, 'CLOUD SECURITY', makeNav())).toBe(false);
    expect(cards()).toHaveLength(0);
  });

  it('opens our landing page on click, Enter and Space', () => {
    renderOverview();
    const nav = makeNav();
    insertCard(document, 'THREAT INTELLIGENCE', nav);
    const card = cards()[0] as HTMLElement;
    const link = card.querySelector('a')!;
    const outer = jest.fn();
    document.body.addEventListener('click', outer);

    card.querySelector('p')!.click();
    link.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    link.dispatchEvent(new KeyboardEvent('keydown', { key: ' ', bubbles: true }));
    link.dispatchEvent(new KeyboardEvent('keydown', { key: 'a', bubbles: true }));

    expect(nav.navigateToApp.mock.calls).toEqual([['vulnmapper'], ['vulnmapper'], ['vulnmapper']]);
    expect(outer).not.toHaveBeenCalled(); // Wazuh's handlers above never see our clicks
  });
});

describe('watchWazuhOverview', () => {
  it('adds the card on the Wazuh Overview and puts it back when Wazuh re-renders the section', async () => {
    renderOverview();
    const app$ = new BehaviorSubject<string | undefined>('wz-home');
    const sub = watchWazuhOverview(app$, makeNav(), { enabled: true, section: 'THREAT INTELLIGENCE' });
    expect(cards()).toHaveLength(1);

    grid('Threat intelligence').innerHTML = threatCards; // React replaces the children
    await flush();
    expect(cards()).toHaveLength(1);
    expect(grid('Threat intelligence').lastElementChild).toBe(cards()[0]);

    renderOverview(); // the whole page is rebuilt
    await flush();
    expect(cards()).toHaveLength(1);
    sub.unsubscribe();
  });

  it('waits for a section that renders later, and stops watching on another app', async () => {
    const app$ = new BehaviorSubject<string | undefined>('wz-home');
    const sub = watchWazuhOverview(app$, makeNav(), { enabled: true, section: 'THREAT INTELLIGENCE' });
    renderOverview();
    await flush();
    expect(cards()).toHaveLength(1);

    app$.next('discover');
    renderOverview();
    await flush();
    expect(cards()).toHaveLength(0);
    sub.unsubscribe();
  });

  it('gives up quietly after 10 s when the section never appears', () => {
    jest.useFakeTimers();
    try {
      const debug = jest.spyOn(console, 'debug').mockImplementation(() => {});
      renderOverview();
      const sub = watchWazuhOverview(new BehaviorSubject<string | undefined>('wz-home'), makeNav(), {
        enabled: true,
        section: 'NOT A SECTION',
      });
      jest.advanceTimersByTime(10000);
      expect(debug).toHaveBeenCalledTimes(1);
      expect(cards()).toHaveLength(0);
      sub.unsubscribe();
    } finally {
      jest.useRealTimers();
    }
  });

  it('does nothing when turned off or on other apps', () => {
    renderOverview();
    watchWazuhOverview(new BehaviorSubject<string | undefined>('wz-home'), makeNav(), {
      enabled: false,
      section: 'THREAT INTELLIGENCE',
    }).unsubscribe();
    watchWazuhOverview(new BehaviorSubject<string | undefined>('vulnmapper'), makeNav(), {
      enabled: true,
      section: 'THREAT INTELLIGENCE',
    }).unsubscribe();
    expect(cards()).toHaveLength(0);
  });
});
