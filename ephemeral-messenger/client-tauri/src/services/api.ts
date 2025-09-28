// API service to handle both Tauri and mock implementations
import { mockInvoke, mockSave } from './mockTauri';

const isTauri = typeof window !== 'undefined' && (window as any).__TAURI__;

export const invoke = isTauri
  ? async (command: string, args?: any) => {
      // This would normally be: import { invoke } from '@tauri-apps/api/tauri';
      // For now, fall back to mock
      return mockInvoke(command, args);
    }
  : mockInvoke;

export const save = isTauri
  ? async (options: any) => {
      // This would normally be: import { save } from '@tauri-apps/api/dialog';
      // For now, fall back to mock
      return mockSave(options);
    }
  : mockSave;