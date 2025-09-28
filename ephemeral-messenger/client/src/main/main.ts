import { app, BrowserWindow, ipcMain, dialog, Menu } from 'electron';
import * as path from 'path';
import { CryptoManager } from './crypto/crypto-manager';
import { SecurityChecker } from './security/security-checker';
import { TorManager } from './tor/tor-manager';
import { SecureStorage } from './storage/secure-storage';

// Handle creating/removing shortcuts on Windows when installing/uninstalling.
if (require('electron-squirrel-startup')) {
  app.quit();
}

class EphemeralMessengerApp {
  private mainWindow: BrowserWindow | null = null;
  private cryptoManager: CryptoManager | null = null;
  private securityChecker: SecurityChecker | null = null;
  private torManager: TorManager | null = null;
  private secureStorage: SecureStorage | null = null;

  constructor() {
    this.setupApp();
    this.setupIPC();
  }

  private setupApp(): void {
    // This method will be called when Electron has finished initialization
    app.whenReady().then(() => {
      this.createWindow();
      this.initializeManagers();
    });

    // Quit when all windows are closed
    app.on('window-all-closed', () => {
      this.performSecureShutdown();
      if (process.platform !== 'darwin') {
        app.quit();
      }
    });

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) {
        this.createWindow();
      }
    });

    // Security: Prevent new window creation
    app.on('web-contents-created', (event, contents) => {
      contents.on('new-window', (event, navigationUrl) => {
        event.preventDefault();
        console.warn('Blocked attempt to open new window:', navigationUrl);
      });

      contents.on('will-navigate', (event, navigationUrl) => {
        const parsedUrl = new URL(navigationUrl);
        if (parsedUrl.origin !== 'file://') {
          event.preventDefault();
          console.warn('Blocked navigation to external URL:', navigationUrl);
        }
      });
    });
  }

  private createWindow(): void {
    // Create the browser window
    this.mainWindow = new BrowserWindow({
      height: 800,
      width: 1200,
      webPreferences: {
        preload: path.join(__dirname, 'preload.js'),
        nodeIntegration: false,
        contextIsolation: true,
        sandbox: true,
        webSecurity: true,
        allowRunningInsecureContent: false,
        experimentalFeatures: false,
      },
      autoHideMenuBar: true,
      show: false, // Don't show until ready
      titleBarStyle: 'default',
    });

    // Load the index.html of the app
    if (MAIN_WINDOW_VITE_DEV_SERVER_URL) {
      this.mainWindow.loadURL(MAIN_WINDOW_VITE_DEV_SERVER_URL);
    } else {
      this.mainWindow.loadFile(path.join(__dirname, `../renderer/${MAIN_WINDOW_VITE_NAME}/index.html`));
    }

    // Show window when ready
    this.mainWindow.once('ready-to-show', () => {
      this.mainWindow?.show();
    });

    // Open DevTools in development
    if (process.env.NODE_ENV === 'development') {
      this.mainWindow.webContents.openDevTools();
    }

    // Handle window closed
    this.mainWindow.on('closed', () => {
      this.performSecureShutdown();
      this.mainWindow = null;
    });

    // Security: Disable menu in production
    if (process.env.NODE_ENV === 'production') {
      Menu.setApplicationMenu(null);
    }
  }

  private async initializeManagers(): Promise<void> {
    try {
      // Initialize secure storage first
      this.secureStorage = new SecureStorage();
      await this.secureStorage.initialize();

      // Initialize security checker
      this.securityChecker = new SecurityChecker();

      // Initialize crypto manager
      this.cryptoManager = new CryptoManager(this.secureStorage);
      await this.cryptoManager.initialize();

      // Initialize Tor manager
      this.torManager = new TorManager();
      await this.torManager.initialize();

      console.log('All managers initialized successfully');
    } catch (error) {
      console.error('Failed to initialize managers:', error);
      this.showErrorDialog('Initialization Failed',
        'Failed to initialize security components. Please check your system and try again.');
      app.quit();
    }
  }

  private setupIPC(): void {
    // Crypto operations
    ipcMain.handle('crypto:generateIdentity', async () => {
      return await this.cryptoManager?.generateIdentity();
    });

    ipcMain.handle('crypto:exportPublicKey', async () => {
      return await this.cryptoManager?.exportPublicKey();
    });

    ipcMain.handle('crypto:encryptMessage', async (event, message: string, recipientPublicKey: string) => {
      return await this.cryptoManager?.encryptMessage(message, recipientPublicKey);
    });

    ipcMain.handle('crypto:decryptMessage', async (event, encryptedMessage: string) => {
      return await this.cryptoManager?.decryptMessage(encryptedMessage);
    });

    // Security checks
    ipcMain.handle('security:runPreSendChecks', async () => {
      return await this.securityChecker?.runPreSendChecks();
    });

    ipcMain.handle('security:checkTorConnection', async () => {
      return await this.torManager?.checkConnection();
    });

    ipcMain.handle('security:checkSwapStatus', async () => {
      return await this.securityChecker?.checkSwapStatus();
    });

    ipcMain.handle('security:checkMemoryLock', async () => {
      return await this.securityChecker?.checkMemoryLock();
    });

    // Tor operations
    ipcMain.handle('tor:createOnionService', async () => {
      return await this.torManager?.createOnionService();
    });

    ipcMain.handle('tor:deleteOnionService', async () => {
      return await this.torManager?.deleteOnionService();
    });

    ipcMain.handle('tor:getOnionAddress', async () => {
      return await this.torManager?.getOnionAddress();
    });

    // File operations
    ipcMain.handle('file:selectFile', async () => {
      const result = await dialog.showOpenDialog(this.mainWindow!, {
        properties: ['openFile'],
        filters: [
          { name: 'All Files', extensions: ['*'] },
        ],
      });

      if (!result.canceled && result.filePaths.length > 0) {
        return result.filePaths[0];
      }
      return null;
    });

    // Storage operations
    ipcMain.handle('storage:storeEncrypted', async (event, key: string, data: any) => {
      return await this.secureStorage?.storeEncrypted(key, data);
    });

    ipcMain.handle('storage:retrieveEncrypted', async (event, key: string) => {
      return await this.secureStorage?.retrieveEncrypted(key);
    });

    // App operations
    ipcMain.handle('app:getVersion', () => {
      return app.getVersion();
    });

    ipcMain.handle('app:quit', () => {
      this.performSecureShutdown();
      app.quit();
    });
  }

  private async performSecureShutdown(): Promise<void> {
    console.log('Performing secure shutdown...');

    try {
      // Wipe crypto manager
      if (this.cryptoManager) {
        await this.cryptoManager.secureWipe();
        this.cryptoManager = null;
      }

      // Cleanup Tor
      if (this.torManager) {
        await this.torManager.cleanup();
        this.torManager = null;
      }

      // Wipe secure storage
      if (this.secureStorage) {
        await this.secureStorage.secureWipe();
        this.secureStorage = null;
      }

      // Force garbage collection
      if (global.gc) {
        global.gc();
      }

      console.log('Secure shutdown completed');
    } catch (error) {
      console.error('Error during secure shutdown:', error);
    }
  }

  private showErrorDialog(title: string, message: string): void {
    dialog.showErrorBox(title, message);
  }
}

// Global variables injected by Vite
declare const MAIN_WINDOW_VITE_DEV_SERVER_URL: string;
declare const MAIN_WINDOW_VITE_NAME: string;

// Initialize the app
new EphemeralMessengerApp();