module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  transform: { '^.+\\.ts$': ['ts-jest', { tsconfig: { module: 'commonjs', esModuleInterop: true } }] },
};
