import { defineConfig } from 'vite';
import { resolve } from 'path';
import { fileURLToPath, URL } from 'node:url';

export default defineConfig(({ command }) => {
  if (command === 'serve') {
    // Development server configuration
    return {
      server: {
        port: 5173,
        open: false
      },
      optimizeDeps: {
        include: ['@noble/curves/p256', 'idb-keyval']
      }
    };
  } else {
    // Build configuration
    return {
      build: {
        lib: {
          entry: resolve(fileURLToPath(new URL('.', import.meta.url)), 'src/index.js'),
          name: 'Unsea',
          fileName: (format) => {
            if (format === 'es') return 'unsea.mjs';
            return `unsea.${format}.js`;
          },
          formats: ['es']
        },
        rollupOptions: {
          external: [],
          output: {
            globals: {}
          }
        },
        target: 'es2020',
        minify: 'terser'
      },
      define: {
        'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV || 'production')
      },
      optimizeDeps: {
        include: ['@noble/curves/p256', 'idb-keyval']
      }
    };
  }
});
