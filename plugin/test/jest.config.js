// Unit tests for the plugin's pure helpers, run with the dashboard's own jest
// and babel setup. From the dashboard folder:
//   node scripts/jest --config plugins/vulnmapper/test/jest.config.js

// The page snapshots show clock times, recorded in Pakistan time; every run
// renders them there, so a machine in another zone (CI runs in UTC) matches.
process.env.TZ = 'Asia/Karachi';

module.exports = {
  rootDir: '../../..', // the dashboard checkout (this folder is plugins/vulnmapper/test)
  roots: ['<rootDir>/plugins/vulnmapper'],
  testMatch: ['**/*.test.{ts,tsx}'],
  testPathIgnorePatterns: ['/node_modules/', '/build/', '/target/'],
  modulePathIgnorePatterns: ['<rootDir>/plugins/vulnmapper/build/', '<rootDir>/plugins/vulnmapper/target/'],
  moduleFileExtensions: ['js', 'json', 'ts', 'tsx'],
  transform: { '^.+\\.(js|tsx?)$': '<rootDir>/src/dev/jest/babel_transform.js' },
  testEnvironment: 'node',
};
