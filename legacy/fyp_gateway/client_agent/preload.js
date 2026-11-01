// fyp_gateway/client_agent/preload.js

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // Window Titlebar Controls
  sendMinimize: () => ipcRenderer.send('window-minimize'),
  sendMaximize: () => ipcRenderer.send('window-maximize'),
  sendClose: () => ipcRenderer.send('window-close'),

  // Tunnel Controls via IPC Main Process Bridge
  connectTunnel: (data) => ipcRenderer.invoke('tunnel:connect', data),
  disconnectTunnel: () => ipcRenderer.invoke('tunnel:disconnect'),

  // Local Backend Privileges Check (Direct Core Fetch)
  checkPrivileges: async () => {
    try {
      const response = await fetch('http://127.0.0.1:8001/v1/client/privileges');
      return await response.json();
    } catch (err) {
      return { is_privileged: false, diagnostic_msg: "Local Core Unreachable." };
    }
  }
});