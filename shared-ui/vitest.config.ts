import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';

// Component tests run in jsdom against the in-memory FakeMeridianClientAdapter — no real core,
// crypto, or network (task 12.2). `adapter.test.ts` is DOM-independent but harmless under jsdom.
export default defineConfig({
  plugins: [svelte(), svelteTesting()],
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.ts'],
    globals: true
  }
});
