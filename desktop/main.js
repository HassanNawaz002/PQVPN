// fyp_gateway/client_agent/main.js
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow = null;
let pyBackendProcess = null;

function startLocalBackend() {
  const scriptPath = path.join(__dirname, 'backend_core', 'local_api.py');
  const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';

  console.log(`[*] Spawning Core Python Subprocess: ${pythonCmd} "${scriptPath}"`);

  pyBackendProcess = spawn(pythonCmd, ['-u', scriptPath], {
    env: { ...process.env, PYTHONUNBUFFERED: '1' }
  });

  pyBackendProcess.stdout.on('data', (data) => {
    const lines = data.toString().trim().split('\n');
    lines.forEach((line) => {
      if (line) console.log(`[Python Core STDOUT]: ${line}`);
    });
  });

  pyBackendProcess.stderr.on('data', (data) => {
    const lines = data.toString().trim().split('\n');
    lines.forEach((line) => {
      if (line) console.error(`[Python Core STDERR]: ${line}`);
    });
  });

  pyBackendProcess.on('close', (code) => {
    console.log(`[Python Core] Subprocess exited with status code: ${code}`);
  });

  pyBackendProcess.on('error', (err) => {
    console.error(`[-] Failed to start Python process: ${err.message}`);
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 700,
    minWidth: 1000,
    minHeight: 600,
    frame: false,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  mainWindow.loadFile(path.join(__dirname, 'index.html')).catch((err) => {
    console.error("[-] Failed to load index.html:", err);
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Window Titlebar Control IPCs
ipcMain.on('window-minimize', () => {
  if (mainWindow) mainWindow.minimize();
});

ipcMain.on('window-maximize', () => {
  if (mainWindow) {
    mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize();
  }
});

ipcMain.on('window-close', () => {
  if (pyBackendProcess) {
    console.log('[Electron Main] Terminating Python process...');
    pyBackendProcess.kill();
  }
  app.quit();
});

// ==========================================
// 🚀 TUNNEL CONNECT IPC HANDLER (YAHAN ADD KAREIN)
// ==========================================
ipcMain.handle('tunnel:connect', async (event, config) => {
  console.log('[Electron Main] Initiating tunnel connection to:', config.gateway_ip);

  // Yahan Python backend agent ko request trigger hogi
  return { 
    status: 'success', 
    serverIp: config.gateway_ip, 
    virtualIp: '10.8.0.5' 
  };
});

// App Lifecycle
app.whenReady().then(() => {
  startLocalBackend();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (pyBackendProcess) pyBackendProcess.kill();
  if (process.platform !== 'darwin') app.quit();
});

app.on('will-quit', () => {
  if (pyBackendProcess) pyBackendProcess.kill();
});