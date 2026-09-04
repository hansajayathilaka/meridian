export type {
  MeridianClientAdapter,
  MeridianId,
  PubkeyHex,
  SafetyNumber,
  TrustState,
  SendGateState,
  Contact,
  ConversationSummary,
  MessageDirection,
  MessageDeliveryState,
  ChatMessage,
  MessageRequest,
  SendResult,
  StreamHandle,
  StreamOpenResult,
  FileTransferSummary,
} from "./adapter";
export { MeridianAdapterError } from "./adapter";

export { FakeMeridianClientAdapter } from "./fake-adapter";

export { default as ContactRow } from "./components/ContactRow.svelte";
export { default as MessageList } from "./components/MessageList.svelte";
export { default as LayoutShell } from "./components/LayoutShell.svelte";

// Screens (task 12.7) — reusable unmodified by both the browser (12.14) and desktop (12.15) shells.
export { default as CreateAccount } from "../screens/CreateAccount.svelte";
export { default as Contacts } from "../screens/Contacts.svelte";
export { default as Chat } from "../screens/Chat.svelte";
export { default as MessageRequests } from "../screens/MessageRequests.svelte";
export { default as Verification } from "../screens/Verification.svelte";
export { default as FileTransfer } from "../screens/FileTransfer.svelte";

export { MediaDevicesQrScanner } from "./qrScanner";
export type { QrScanner, QrScanOutcome } from "./qrScanner";

export { createAccountStore } from "../screens/stores/accountStore";
export type { CreateAccountState, CreateAccountStore } from "../screens/stores/accountStore";
export { createContactsStore } from "../screens/stores/contactsStore";
export type { ContactsState, ContactsStore } from "../screens/stores/contactsStore";
export { createChatStore } from "../screens/stores/chatStore";
export type { ChatState, ChatStore } from "../screens/stores/chatStore";
export { createMessageRequestsStore } from "../screens/stores/messageRequestsStore";
export type {
  MessageRequestsState,
  MessageRequestsStore,
} from "../screens/stores/messageRequestsStore";
export { createVerificationStore, compareSafetyNumbers } from "../screens/stores/verificationStore";
export type {
  VerificationState,
  VerificationStore,
  ScanComparison,
} from "../screens/stores/verificationStore";
export {
  createFileTransferStore,
  transferPercent,
  transferStateLabel,
} from "../screens/stores/fileTransferStore";
export type { FileTransferState, FileTransferStore } from "../screens/stores/fileTransferStore";
