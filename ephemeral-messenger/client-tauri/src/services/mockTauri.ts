// Mock Tauri API for development without Rust backend
import { Identity, Message, Contact, EncryptedMessage } from '../types';

// Mock storage for development
const mockStorage = {
  identity: null as Identity | null,
  contacts: [] as Contact[],
  messages: [] as Message[],
};

export const mockInvoke = async <T>(command: string, args?: any): Promise<T> => {
  console.log(`Mock invoke: ${command}`, args);

  await new Promise(resolve => setTimeout(resolve, 100)); // Simulate async

  switch (command) {
    case 'get_current_identity':
      return mockStorage.identity as T;

    case 'create_identity':
      const newIdentity: Identity = {
        fingerprint: 'MOCK' + Math.random().toString(36).substring(2, 15).toUpperCase(),
        public_identity: 'mock_public_key_' + Date.now(),
        created_at: Date.now(),
      };
      mockStorage.identity = newIdentity;
      return newIdentity as T;

    case 'import_identity':
      const importedIdentity: Identity = {
        fingerprint: 'IMPORT' + Math.random().toString(36).substring(2, 15).toUpperCase(),
        public_identity: 'imported_public_key_' + Date.now(),
        created_at: Date.now(),
      };
      mockStorage.identity = importedIdentity;
      return importedIdentity as T;

    case 'get_contacts':
      return mockStorage.contacts as T;

    case 'add_contact':
      const contact = args.contact as Contact;
      if (!mockStorage.contacts.find(c => c.fingerprint === contact.fingerprint)) {
        mockStorage.contacts.push({
          ...contact,
          public_key: contact.public_key || 'mock_public_key_' + contact.fingerprint,
        });
      }
      return true as T;

    case 'get_messages':
      const contactFingerprint = args.contactFingerprint;
      return mockStorage.messages.filter(
        m => m.sender_fingerprint === contactFingerprint ||
             m.recipient_fingerprint === contactFingerprint
      ) as T;

    case 'encrypt_message':
      const encryptedMsg: EncryptedMessage = {
        encrypted_data: 'ENCRYPTED_' + btoa(args.message),
        sender_public_key: mockStorage.identity?.public_identity || 'unknown',
        timestamp: Date.now(),
      };
      return encryptedMsg as T;

    case 'decrypt_message':
      const encryptedData = args.encrypted_message.encrypted_data;
      if (encryptedData.startsWith('ENCRYPTED_')) {
        const decrypted = atob(encryptedData.replace('ENCRYPTED_', ''));
        return decrypted as T;
      }
      throw new Error('Failed to decrypt message');

    case 'store_message':
      const message = args.message as Message;
      mockStorage.messages.push(message);
      return true as T;

    case 'create_document':
      const mockPath = '/tmp/mock_document_' + Date.now() + '.securedoc';
      return { file_path: mockPath } as T;

    case 'save_document_to_path':
      console.log(`Mock: Saving document from ${args.sourcePath} to ${args.targetPath}`);
      return true as T;

    default:
      throw new Error(`Mock: Unknown command ${command}`);
  }
};

export const mockSave = async (options: any): Promise<string | null> => {
  console.log('Mock save dialog:', options);
  // Return a mock file path
  return `/tmp/mock_save_${Date.now()}.securedoc`;
};