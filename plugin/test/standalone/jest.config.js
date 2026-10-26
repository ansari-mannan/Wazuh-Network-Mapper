// The plugin's tests without a dashboard checkout. From this folder:
//   npm install
//   npm test
// The same tests, transform and environment as ../jest.config.js (the
// dashboard's own jest, which stays the reference): the packages come from
// this folder's node_modules, at the versions OpenSearch Dashboards 2.19.3
// locks, and the dashboard's unpublished packages from osd/ (copied from that
// release, and one stand-in; see osd/README.md).
const path = require('path');

// as ../jest.config.js: the page snapshots' clock times are in Pakistan time
process.env.TZ = 'Asia/Karachi';

const here = __dirname;
const osd = (file) => path.join(here, 'osd', file);

module.exports = {
  rootDir: path.resolve(here, '../..'), // the plugin folder
  roots: ['<rootDir>/public', '<rootDir>/server', '<rootDir>/common'],
  testMatch: ['**/*.test.{ts,tsx}'],
  testPathIgnorePatterns: ['/node_modules/', '/build/', '/target/'],
  modulePathIgnorePatterns: ['<rootDir>/build/', '<rootDir>/target/'],
  moduleFileExtensions: ['js', 'json', 'ts', 'tsx'],
  // the plugin's own files find their packages here
  modulePaths: [path.join(here, 'node_modules')],
  moduleNameMapper: {
    '^@osd/config-schema$': osd('config-schema/index.ts'),
    '^@osd/ui-shared-deps/theme$': osd('ui-shared-deps/theme.ts'),
    '^@osd/i18n/react$': osd('i18n/react.tsx'),
    // OUI requires it; on npm the name is only a security placeholder
    '^@opensearch/datemath$': osd('datemath/index.js'),
  },
  // @osd/babel-preset's node_preset, without the core-js polyfill entry
  transform: {
    '^.+\\.(js|tsx?)$': [
      require.resolve('babel-jest'),
      {
        babelrc: false,
        configFile: false,
        presets: [
          [require.resolve('@babel/preset-env'), { targets: { node: 14 }, modules: 'cjs' }],
          [require.resolve('@babel/preset-typescript'), { allowNamespaces: true }],
          require.resolve('@babel/preset-react'),
        ],
        plugins: [
          require.resolve('@babel/plugin-transform-class-properties'),
          require.resolve('@babel/plugin-transform-private-methods'),
          require.resolve('babel-plugin-add-module-exports'),
        ],
      },
    ],
  },
  testEnvironment: 'node',
};
