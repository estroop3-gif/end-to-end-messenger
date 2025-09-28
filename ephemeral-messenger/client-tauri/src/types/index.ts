export interface Identity {
  fingerprint: string;
  public_identity: string;
  created_at: number;
}

export interface Message {
  id: string;
  sender_fingerprint: string;
  recipient_fingerprint: string;
  content: string;
  timestamp: number;
  encrypted_content: string;
}

export interface Document {
  id: string;
  title: string;
  content: string;
  author_fingerprint: string;
  recipients: string[];
  created_at: number;
  expires_at?: number;
  policy: DocumentPolicy;
}

export interface DocumentPolicy {
  auto_expire_hours?: number;
  max_open_count?: number;
  offline_open_allowed: boolean;
  require_hardware_token: boolean;
  watermark_enabled: boolean;
}

export interface EncryptedMessage {
  encrypted_data: string;
  sender_public_key: string;
  timestamp: number;
}

export interface DecryptMessageRequest {
  encrypted_message: EncryptedMessage;
  passphrase: string;
}

export interface EncryptMessageRequest {
  message: string;
  recipient_public_key: string;
  passphrase: string;
}

export interface CreateDocumentRequest {
  title: string;
  content: string;
  recipients: string[];
  policy: DocumentPolicy;
  passphrase: string;
}

export interface EncryptedDocument {
  file_path: string;
  manifest: DocumentManifest;
}

export interface DocumentManifest {
  title: string;
  author_fingerprint: string;
  recipients: string[];
  created_at: number;
  expires_at?: number;
  policy: DocumentPolicy;
  content_type: string;
  content_hash: string;
  version: string;
}

export interface Contact {
  fingerprint: string;
  name: string;
  public_key: string;
  last_seen?: number;
}

// Login System Types
export interface LoginResponse {
  ok: boolean;
  error?: string;
}

export interface HardKeyStatus {
  present: boolean;
  fingerprint?: string;
  device_path?: string;
}

export interface SettingsResponse {
  version: number;
  access_mode: string;
  has_credential: boolean;
  updated_at: number;
}