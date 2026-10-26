# Dashboard packages for the standalone test run

The plugin, and OUI, import some of the dashboard's internal packages, which
are not published on npm. `../jest.config.js` maps them here:

| Import | Here | From |
|---|---|---|
| `@osd/config-schema` | `config-schema/` | OpenSearch Dashboards 2.19.3, `packages/osd-config-schema/src` (tests left out), unchanged |
| `@osd/ui-shared-deps/theme` | `ui-shared-deps/theme.ts` | OpenSearch Dashboards 2.19.3, `packages/osd-ui-shared-deps/theme.ts`, unchanged |
| `@opensearch/datemath` | `datemath/index.js` | OpenSearch Dashboards 2.19.3, `packages/opensearch-datemath/index.js`, unchanged. OUI requires it; the npm package of that name is only a security placeholder, so never install it from npm |
| `@osd/i18n/react` | `i18n/react.tsx` | a stand-in: `I18nProvider` renders its children |

The copied files are Apache-2.0 (`LICENSE.txt`, from the same release) and
keep their own headers. When the plugin moves to another dashboard version,
copy them again from that release.
