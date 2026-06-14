import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    // Preserve symlinks so that testing in workspace directories containing special characters
    // (like '#') using a directory symlink or junction resolves imports correctly without breaking.
    preserveSymlinks: true,
  },
  plugins: [
    {
      name: 'remove-shebang',
      enforce: 'pre',
      transform(code, id) {
        if (id.endsWith('.js') || id.endsWith('.ts')) {
          return code.replace(/^#!\/.*/, '');
        }
      },
    },
  ],
  test: {
    environment: 'node',
    globals: true,
    include: ['test/**/*.test.js'],
    setupFiles: ['test/setup.js'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      include: ['src/**/*.js'],
      exclude: ['src/index.js', 'src/config/db.js'],
    },
  },
});

