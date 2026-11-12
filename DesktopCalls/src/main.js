import { Room, RoomEvent, Track } from "livekit-client";
import { createInvitation, parseInvitation } from "./invitation.js";

const byId = (id) => document.getElementById(id);
const apiInput = byId("api-url");
const nameInput = byId("display-name");
const invitationInput = byId("invitation");
const callMessage = byId("call-message");
const callStatus = byId("call-status");
const connectPill = byId("connection-pill");
const connectLabel = byId("connection-label");
const leaveButton = byId("leave-call");
const muteButton = byId("mute-mic");
const cameraButton = byId("toggle-camera");
const invitationCard = byId("invitation-card");
const videoGrid = byId("video-grid");
const localTile = byId("local-tile");
const localVideo = byId("local-video");
const audioLayer = byId("audio-layer");

let room = null;
let currentInvitation = "";
let connecting = false;

apiInput.value = localStorage.getItem("callingApiUrl") || "";
nameInput.value = localStorage.getItem("callingDisplayName") || "";

function setMessage(message, isError) {
  callMessage.textContent = message;
  callMessage.classList.toggle("error", Boolean(isError));
}

function setConnected(connected, label) {
  connectPill.classList.toggle("connected", connected);
  connectLabel.textContent = label;
}

function setBusy(value) {
  connecting = value;
  ["create-voice", "create-video", "join-call"].forEach((id) => {
    byId(id).disabled = value || room !== null;
  });
}

function validatedInputs() {
  const apiUrl = apiInput.value.trim();
  const displayName = nameInput.value.trim();
  if (!apiUrl) throw new Error("Enter the HTTPS calling service URL.");
  if (!displayName || displayName.length > 32 || /[\u0000-\u001f\u007f]/.test(displayName)) {
    throw new Error("Enter a display name between 1 and 32 characters.");
  }
  localStorage.setItem("callingApiUrl", apiUrl);
  localStorage.setItem("callingDisplayName", displayName);
  return { apiUrl, displayName };
}

async function postCallApi(apiUrl, path, body) {
  const result = await window.desktopCalls.post(apiUrl, path, body);
  if (!result.ok) {
    const messages = {
      invitation_expired_or_unknown: "This invitation has expired or is not valid.",
      invalid_invitation_code: "The invitation code is not valid.",
      invalid_display_name: "The calling service did not accept that display name.",
      rate_limited: "Too many call requests were made. Please wait and try again.",
      call_service_unavailable: "The call service is temporarily unavailable."
    };
    const message = messages[result.error] || result.error || "The calling service returned an error.";
    throw new Error(message);
  }
  return result.body;
}

function safeParticipantName(participant) {
  return (participant.name || participant.identity || "Guest").slice(0, 32);
}

function addParticipant(participant) {
  const id = "participant-" + participant.identity.replace(/[^A-Za-z0-9_-]/g, "_");
  if (document.getElementById(id)) return;
  const tile = document.createElement("div");
  tile.className = "video-placeholder";
  tile.id = id;
  tile.dataset.identity = participant.identity;
  const label = document.createElement("span");
  label.className = "tile-label";
  label.textContent = safeParticipantName(participant);
  tile.appendChild(label);
  videoGrid.appendChild(tile);
}

function removeParticipant(identity) {
  const id = "participant-" + identity.replace(/[^A-Za-z0-9_-]/g, "_");
  const tile = document.getElementById(id);
  if (tile) tile.remove();
}

function attachTrack(track, participant) {
  if (track.kind === Track.Kind.Video) {
    addParticipant(participant);
    const id = "participant-" + participant.identity.replace(/[^A-Za-z0-9_-]/g, "_");
    const tile = document.getElementById(id);
    if (!tile) return;
    const video = track.attach();
    video.autoplay = true;
    video.playsInline = true;
    video.className = "remote-video";
    tile.prepend(video);
  } else if (track.kind === Track.Kind.Audio) {
    const audio = track.attach();
    audio.autoplay = true;
    audioLayer.appendChild(audio);
  }
}

function refreshParticipants() {
  if (!room) return;
  callStatus.textContent = "Connected · " + (room.remoteParticipants.size + 1) + " participant" +
    (room.remoteParticipants.size === 0 ? "" : "s");
  room.remoteParticipants.forEach(addParticipant);
}

function attachRoomEvents(activeRoom) {
  activeRoom
    .on(RoomEvent.TrackSubscribed, (track, publication, participant) => attachTrack(track, participant))
    .on(RoomEvent.TrackUnsubscribed, (track, publication, participant) => {
      track.detach().forEach((element) => element.remove());
    })
    .on(RoomEvent.ParticipantConnected, (participant) => {
      addParticipant(participant);
      refreshParticipants();
    })
    .on(RoomEvent.ParticipantDisconnected, (participant) => {
      removeParticipant(participant.identity);
      refreshParticipants();
    })
    .on(RoomEvent.Disconnected, () => {
      if (room === activeRoom) {
        finishCall(false);
        setMessage("Call ended or the connection was lost.", true);
      }
    });
}

async function joinRoom(apiUrl, displayName, invitation, withVideo) {
  const parsed = parseInvitation(invitation);
  currentInvitation = invitation;
  invitationInput.value = invitation;
  setMessage("Requesting a short-lived participant token…", false);
  const credentials = await postCallApi(apiUrl, "/api/token", {
    invitationCode: parsed.code,
    displayName
  });
  if (!credentials.serverUrl || !credentials.token) {
    throw new Error("The calling service returned incomplete connection details.");
  }
  let signalingUrl;
  try {
    signalingUrl = new URL(credentials.serverUrl);
  } catch {
    throw new Error("The calling service returned an invalid media-server URL.");
  }
  const localHost = signalingUrl.hostname === "localhost" ||
    signalingUrl.hostname === "127.0.0.1" || signalingUrl.hostname === "[::1]";
  if (signalingUrl.protocol !== "wss:" &&
      !(signalingUrl.protocol === "ws:" && localHost)) {
    throw new Error("Calls require secure WebSocket signaling.");
  }

  const activeRoom = new Room({ adaptiveStream: true, dynacast: true });
  room = activeRoom;
  attachRoomEvents(activeRoom);
  await activeRoom.connect(credentials.serverUrl, credentials.token);
  await activeRoom.localParticipant.setMicrophoneEnabled(true);
  if (withVideo) await activeRoom.localParticipant.setCameraEnabled(true);

  const camera = activeRoom.localParticipant.getTrackPublication(Track.Source.Camera);
  if (camera && camera.track) camera.track.attach(localVideo);
  localTile.classList.toggle("has-video", Boolean(camera && camera.track));
  localTile.classList.toggle("is-self", true);
  muteButton.disabled = false;
  cameraButton.disabled = false;
  leaveButton.disabled = false;
  cameraButton.textContent = withVideo ? "Turn camera off" : "Turn camera on";
  muteButton.textContent = "Mute mic";
  invitationCard.hidden = false;
  byId("copy-invitation").disabled = false;
  setConnected(true, "Connected to calling service");
  setMessage("Call connected. Share the complete private invitation with your friend.", false);
  refreshParticipants();
}

async function runCall(action) {
  if (connecting || room) return;
  setBusy(true);
  try {
    const { apiUrl, displayName } = validatedInputs();
    await action(apiUrl, displayName);
  } catch (error) {
    setConnected(false, "Ready when you are");
    setMessage(error.message || "Could not start the call.", true);
    callStatus.textContent = "Not in a call";
    finishCall(true);
  } finally {
    setBusy(false);
  }
}

async function createCall(apiUrl, displayName, withVideo) {
  setMessage("Creating a private invitation…", false);
  const created = await postCallApi(apiUrl, "/api/rooms", {});
  const key = crypto.getRandomValues(new Uint8Array(32));
  const invitation = createInvitation(created.invitationCode, key);
  await joinRoom(apiUrl, displayName, invitation, withVideo);
}

async function joinExistingCall(apiUrl, displayName) {
  const invitation = invitationInput.value.trim();
  parseInvitation(invitation);
  await joinRoom(apiUrl, displayName, invitation, false);
}

function finishCall(disconnect) {
  const previousRoom = room;
  room = null;
  if (disconnect && previousRoom) previousRoom.disconnect();
  localVideo.srcObject = null;
  localTile.classList.remove("has-video", "is-self");
  videoGrid.querySelectorAll("[data-identity]").forEach((tile) => tile.remove());
  audioLayer.replaceChildren();
  muteButton.disabled = true;
  cameraButton.disabled = true;
  leaveButton.disabled = true;
  invitationCard.hidden = true;
  byId("copy-invitation").disabled = true;
  callStatus.textContent = "Not in a call";
  setConnected(false, "Ready when you are");
  setBusy(false);
  if (!connecting) setMessage("Start a call or paste an invitation to join.", false);
}

byId("create-voice").addEventListener("click", () =>
  runCall((apiUrl, name) => createCall(apiUrl, name, false)));
byId("create-video").addEventListener("click", () =>
  runCall((apiUrl, name) => createCall(apiUrl, name, true)));
byId("join-call").addEventListener("click", () =>
  runCall((apiUrl, name) => joinExistingCall(apiUrl, name)));
leaveButton.addEventListener("click", () => finishCall(true));
muteButton.addEventListener("click", async () => {
  if (!room) return;
  try {
    const enabled = room.localParticipant.isMicrophoneEnabled;
    await room.localParticipant.setMicrophoneEnabled(!enabled);
    muteButton.textContent = enabled ? "Unmute mic" : "Mute mic";
  } catch (error) {
    setMessage(error.message || "Could not change microphone state.", true);
  }
});
cameraButton.addEventListener("click", async () => {
  if (!room) return;
  try {
    const enabled = room.localParticipant.isCameraEnabled;
    await room.localParticipant.setCameraEnabled(!enabled);
    const camera = room.localParticipant.getTrackPublication(Track.Source.Camera);
    if (!enabled && camera && camera.track) camera.track.attach(localVideo);
    if (enabled) localVideo.srcObject = null;
    localTile.classList.toggle("has-video", !enabled);
    cameraButton.textContent = enabled ? "Turn camera on" : "Turn camera off";
  } catch (error) {
    setMessage(error.message || "Could not change camera state.", true);
  }
});
byId("copy-invitation").addEventListener("click", async () => {
  if (!currentInvitation) return;
  try {
    await window.desktopCalls.copyText(currentInvitation);
    setMessage("Private invitation copied. Share it only with people you trust.", false);
  } catch (error) {
    setMessage(error.message || "Could not copy the invitation.", true);
  }
});

window.addEventListener("beforeunload", () => {
  if (room) room.disconnect();
});
