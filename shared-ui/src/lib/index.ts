// shared-ui public entry. The adapter boundary is framework-agnostic TS (ADR 0012); the Svelte
// primitives are the only framework-bound exports.
export * from './adapter';
export { FakeMeridianClientAdapter, type FakeAdapterOptions } from './fake-adapter';
export { contactDisplayLabel, trustLabel, messageStateLabel, connectionLabel } from './view';
export { default as AppShell } from './components/AppShell.svelte';
export { default as ContactRow } from './components/ContactRow.svelte';
export { default as MessageList } from './components/MessageList.svelte';
