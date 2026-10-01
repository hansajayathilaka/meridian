// shared-ui public entry. The adapter boundary is framework-agnostic TS (ADR 0012); the Svelte
// primitives are the only framework-bound exports.
export * from './adapter';
export { FakeMeridianClientAdapter, type FakeAdapterOptions } from './fake-adapter';
export { contactDisplayLabel, trustLabel, messageStateLabel, connectionLabel } from './view';
export { default as AppShell } from './components/AppShell.svelte';
export { default as ContactRow } from './components/ContactRow.svelte';
export { default as MessageList } from './components/MessageList.svelte';
// Core messaging screens (task 12.7) + their view-model stores. Screens talk to the adapter only.
export { default as AccountCreate } from './screens/AccountCreate.svelte';
export { default as Contacts } from './screens/Contacts.svelte';
export { default as Chat } from './screens/Chat.svelte';
export { default as MessageRequests } from './screens/MessageRequests.svelte';
export { AccountCreateViewModel, type ProtectionChoice } from './screens/account-create.svelte';
export { ContactsViewModel } from './screens/contacts.svelte';
export { ChatViewModel, type SendNotice } from './screens/chat.svelte';
export {
  MessageRequestsViewModel,
  type Decision,
  type PendingDecision
} from './screens/message-requests.svelte';
// Verification screen (task 12.8): camera capture is an injectable seam the shell implements.
export { default as Verification } from './screens/Verification.svelte';
export {
  VerificationViewModel,
  type ActionPrompt,
  type CheckState,
  type VerifyNotice
} from './screens/verification.svelte';
export {
  QrScannerError,
  type QrScanFailure,
  type QrScanHandlers,
  type QrScanner,
  type QrScanSession
} from './qr-scanner';
// File-transfer screen (task 12.9): `mrd.file/1` send / progress / receive, purely via the adapter.
export { default as FileTransfer } from './screens/FileTransfer.svelte';
export {
  FileTransferViewModel,
  type OfferDecision,
  type PendingOfferDecision
} from './screens/file-transfer.svelte';
