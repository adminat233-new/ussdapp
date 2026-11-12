const { app, BrowserWindow, clipboard, ipcMain, session } = require("electron");
const path = require("node:path");

let mainWindow;

function validateApiUrl(value) {
  let url;
  try {
    url = new URL(String(value || "").trim());
  } catch {
    throw new Error("Enter a valid HTTPS calling service URL.");
  }
  const localHost = url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if ((url.protocol !== "https:" && !(url.protocol === "http:" && localHost)) ||
      url.username || url.password || url.search || url.hash) {
    throw new Error("Use an HTTPS calling service URL. HTTP is allowed only for localhost.");
  }
  url.pathname = url.pathname.replace(/\/+$/, "") + "/";
  return url;
}

function registerCallApi() {
  ipcMain.handle("call-api-post", async function (event, request) {
    if (!mainWindow || event.sender !== mainWindow.webContents) {
      throw new Error("Untrusted call request.");
    }
    if (!request || (request.path !== "/api/rooms" && request.path !== "/api/token")) {
      throw new Error("Unsupported calling service operation.");
    }
    const url = validateApiUrl(request.apiUrl);
    const endpoint = new URL(request.path.slice(1), url);
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(request.body || {}),
      redirect: "error",
      signal: AbortSignal.timeout(15000)
    });
    const text = await response.text();
    let body;
    try {
      body = text ? JSON.parse(text) : {};
    } catch {
      throw new Error("The calling service returned an invalid response.");
    }
    if (!response.ok) {
      return {
        ok: false,
        status: response.status,
        error: typeof body.error === "string" ? body.error : "Calling service request failed."
      };
    }
    return { ok: true, body: body };
  });

  ipcMain.handle("copy-invitation", function (event, value) {
    if (!mainWindow || event.sender !== mainWindow.webContents ||
        typeof value !== "string" || value.length > 128 ||
        !/^[a-f0-9]{48}:[A-Za-z0-9_-]{43}$/.test(value)) {
      throw new Error("The invitation could not be copied.");
    }
    clipboard.writeText(value);
    return true;
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1060,
    height: 760,
    minWidth: 720,
    minHeight: 580,
    title: "USSD Manager Calls",
    backgroundColor: "#f4f7fb",
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });

  const pagePath = path.resolve(__dirname, "../dist/index.html");
  mainWindow.webContents.on("will-navigate", function (event, target) {
    let targetPath = "";
    try {
      const targetUrl = new URL(target);
      if (targetUrl.protocol === "file:") {
        targetPath = path.resolve(decodeURIComponent(targetUrl.pathname.replace(/^\/([A-Za-z]:)/, "$1")));
      }
    } catch {
      targetPath = "";
    }
    if (targetPath.toLowerCase() !== pagePath.toLowerCase()) event.preventDefault();
  });
  mainWindow.webContents.setWindowOpenHandler(function () {
    return { action: "deny" };
  });
  mainWindow.loadFile(pagePath);
  mainWindow.on("closed", function () {
    mainWindow = null;
  });
}

app.whenReady().then(function () {
  session.defaultSession.setPermissionRequestHandler(function (webContents, permission, callback) {
    const trusted = mainWindow && webContents === mainWindow.webContents;
    callback(Boolean(trusted && permission === "media"));
  });
  registerCallApi();
  createWindow();
  app.on("activate", function () {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", function () {
  if (process.platform !== "darwin") app.quit();
});
