const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("desktopCalls", {
  post: function (apiUrl, path, body) {
    return ipcRenderer.invoke("call-api-post", { apiUrl: apiUrl, path: path, body: body });
  },
  copyText: function (value) {
    return ipcRenderer.invoke("copy-invitation", value);
  }
});
