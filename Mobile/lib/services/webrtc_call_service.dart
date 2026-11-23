import 'dart:async';
import 'dart:convert';

import 'package:flutter_webrtc/flutter_webrtc.dart';

import 'call_config.dart';
import 'relay_service.dart';

/// Live peer-to-peer media over the existing TCP relay's signalling channel.
///
/// This is deliberately narrow and honest:
///  * Signalling (offer / answer / ICE candidate / hangup) travels as
///    `WRTC|<base64 json>` inside the relay's ordinary `MSG` frame, so both
///    peers must be registered and online on the same relay.
///  * The relay stores no unsealed mail. Signalling to an absent peer is
///    refused by the relay; it is not queued here and pretending otherwise
///    would be a lie.
///  * Media is WebRTC/ICE, NOT forwarded by the USSD relay. A STUN server is
///    configured by default; a TURN server must be supplied in Settings for
///    calls across symmetric NAT or restrictive firewalls. Without TURN,
///    "works on every network" cannot be claimed.
///  * There is no common signalling protocol with the Windows UDP/TCP call
///    stack or the iOS LiveKit stack yet. A Flutter peer can call another
///    Flutter peer; cross-client media is source work, not a shipped feature.
enum WebrtcPhase { idle, signalling, connecting, connected, failed }

class WebRtcCallService {
  final RelayService relay;
  final CallConfig callConfig;
  final void Function(WebrtcPhase phase, String detail)? onState;

  WebRtcCallService({
    required this.relay,
    required this.callConfig,
    this.onState,
  });

  final RTCVideoRenderer localRenderer = RTCVideoRenderer();
  final RTCVideoRenderer remoteRenderer = RTCVideoRenderer();

  RTCPeerConnection? _pc;
  MediaStream? _localStream;
  MediaStream? _remoteStream;
  String _peer = '';
  bool _initiator = false;
  bool _video = true;
  bool _remoteDescriptionSet = false;
  bool _initialized = false;
  int _generation = 0;
  final List<Map<String, dynamic>> _pendingCandidates =
      <Map<String, dynamic>>[];

  WebrtcPhase _phase = WebrtcPhase.idle;
  String _detail = 'No active call.';

  WebrtcPhase get phase => _phase;
  String get detail => _detail;
  String get peer => _peer;
  bool get inCall => _pc != null && _peer.isNotEmpty;

  Future<void> init() async {
    if (_initialized) return;
    await WebRTC.initialize();
    await localRenderer.initialize();
    await remoteRenderer.initialize();
    _initialized = true;
  }

  /// Handle an incoming `WRTC|...` frame delivered by RelayService.
  Future<void> handleSignal(String from, String frame) async {
    if (!frame.startsWith('WRTC|')) return;
    final generation = _generation;
    Map<String, dynamic> msg;
    try {
      final decoded = utf8.decode(base64Decode(frame.substring(4)));
      msg = jsonDecode(decoded) as Map<String, dynamic>;
    } catch (_) {
      return;
    }
    final type = msg['t'] as String?;
    // The relay's envelope is the authority for who sent the frame. A `peer`
    // field inside the JSON is display information only; trusting it for
    // routing would let a peer redirect our answers to a third number.
    final peer = from.replaceAll(RegExp(r'[^0-9]'), '');
    if (type == null || peer.isEmpty) return;

    if (type == 'busy') {
      if (_peer.isEmpty || peer == _peer) {
        await _teardown(sendHangup: false);
        _set(WebrtcPhase.failed, 'Peer #$peer is already in a call.');
      }
      return;
    }
    if (type == 'hangup') {
      if (_peer.isEmpty || peer == _peer) {
        await _teardown(sendHangup: false);
        _set(WebrtcPhase.idle, 'Call ended by #$peer.');
      }
      return;
    }
    if (_peer.isNotEmpty && peer != _peer) {
      // A second, unrelated offer must not hijack an active call. Answer with
      // busy instead of silently dropping it so the caller gets a real result.
      if (type == 'offer') _sendTo(peer, <String, dynamic>{'t': 'busy'});
      return;
    }
    if (generation != _generation) return;

    switch (type) {
      case 'offer':
        await _onOffer(peer, msg);
        break;
      case 'answer':
        await _onAnswer(msg);
        break;
      case 'candidate':
        await _onCandidate(msg);
        break;
    }
  }

  /// Place an audio or audio/video call to a registered relay number.
  Future<bool> start({
    required String peerNumber,
    required bool video,
  }) async {
    final peer = peerNumber.trim().replaceAll(RegExp(r'[^0-9]'), '');
    if (!relay.registered) {
      _set(WebrtcPhase.failed, 'Relay is not registered. Configure it in Settings first.');
      return false;
    }
    if (peer.isEmpty) {
      _set(WebrtcPhase.failed, 'Enter the peer 700-XXXXXXX number first.');
      return false;
    }
    if (peer == relay.myNumber.replaceAll(RegExp(r'[^0-9]'), '')) {
      _set(WebrtcPhase.failed, 'You cannot call your own number.');
      return false;
    }
    await init();
    await _teardown(sendHangup: false);
    _pendingCandidates.clear();
    final generation = ++_generation;
    _peer = peer;
    _initiator = true;
    _video = video;
    final ok = await _createPeerConnection(video);
    if (!ok || generation != _generation) return false;
    try {
      final offer = await _pc!.createOffer();
      await _pc!.setLocalDescription(offer);
      _send(<String, dynamic>{'t': 'offer', 'sdp': offer.sdp, 'v': video});
      _set(WebrtcPhase.signalling,
          'Offer sent to #$peer. Waiting for answer (media is direct WebRTC, not relayed).');
      return true;
    } catch (e) {
      await _teardown(sendHangup: false);
      _set(WebrtcPhase.failed, 'Could not create offer: $e');
      return false;
    }
  }

  Future<void> leave() => _teardown(sendHangup: true);

  Future<void> setMicrophoneEnabled(bool enabled) async {
    final stream = _localStream;
    if (stream == null) return;
    for (final track in stream.getAudioTracks()) {
      track.enabled = enabled;
    }
  }

  Future<void> setCameraEnabled(bool enabled) async {
    final stream = _localStream;
    if (stream == null) return;
    for (final track in stream.getVideoTracks()) {
      track.enabled = enabled;
    }
  }

  Future<bool> _createPeerConnection(bool video) async {
    try {
      final configuration = <String, dynamic>{
        'iceServers': callConfig.iceServers(),
        // addTrack() needs unified-plan on the native 0.10 implementation.
        'sdpSemantics': 'unified-plan',
      };
      _pc = await createPeerConnection(configuration);
      final pc = _pc!;
      pc.onIceCandidate = (RTCIceCandidate candidate) {
        _send(<String, dynamic>{
          't': 'candidate',
          'c': <String, dynamic>{
            'candidate': candidate.candidate,
            'sdpMid': candidate.sdpMid,
            'sdpMLineIndex': candidate.sdpMLineIndex,
          },
        });
      };
      pc.onTrack = (RTCTrackEvent event) {
        if (event.streams.isNotEmpty) _attachRemote(event.streams.first);
      };
      // onAddStream is the legacy event still emitted by 0.10 on some hosts.
      pc.onAddStream = (MediaStream stream) => _attachRemote(stream);
      pc.onConnectionState = (RTCPeerConnectionState state) {
        if (state == RTCPeerConnectionState.RTCPeerConnectionStateConnected) {
          _set(WebrtcPhase.connected, 'Media connected to #$_peer.');
        } else if (state ==
            RTCPeerConnectionState.RTCPeerConnectionStateDisconnected) {
          _set(WebrtcPhase.connecting, 'Media link lost; ICE is reconnecting.');
        } else if (state == RTCPeerConnectionState.RTCPeerConnectionStateFailed) {
          _set(WebrtcPhase.failed,
              'Media failed. A TURN server is usually needed across this network path.');
        }
      };

      final constraints = <String, dynamic>{
        'audio': <String, dynamic>{
          'echoCancellation': true,
          'noiseSuppression': true,
        },
        'video': video
            ? <String, dynamic>{
                'facingMode': 'user',
                'width': <String, dynamic>{'ideal': 640},
                'height': <String, dynamic>{'ideal': 480},
              }
            : false,
      };
      final local =
          await navigator.mediaDevices.getUserMedia(constraints);
      _localStream = local;
      localRenderer.srcObject = local;
      for (final track in local.getTracks()) {
        await pc.addTrack(track, local);
      }
      _remoteDescriptionSet = false;
      // Do not clear queued ICE here: candidates for an incoming offer can
      // arrive while getUserMedia is still waiting on a permission prompt.
      return true;
    } catch (e) {
      await _teardown(sendHangup: false);
      _set(WebrtcPhase.failed,
          'Microphone/camera or WebRTC init failed: $e. Check OS permissions.');
      return false;
    }
  }

  Future<void> _onOffer(String peer, Map<String, dynamic> msg) async {
    if (_pc != null) {
      _sendTo(peer, <String, dynamic>{'t': 'busy'});
      return;
    }
    final sdp = msg['sdp'] as String?;
    if (sdp == null || sdp.isEmpty) return;
    final video = msg['v'] is bool ? msg['v'] as bool : true;
    // Clear stale ICE from a previous call before the (possibly slow) init,
    // so candidates that arrive while permissions are pending are retained.
    _pendingCandidates.clear();
    await init();
    final generation = ++_generation;
    _peer = peer;
    _initiator = false;
    _video = video;
    if (!await _createPeerConnection(video) || generation != _generation) return;
    try {
      await _pc!.setRemoteDescription(RTCSessionDescription(sdp, 'offer'));
      _remoteDescriptionSet = true;
      await _flushCandidates();
      final answer = await _pc!.createAnswer();
      await _pc!.setLocalDescription(answer);
      _send(<String, dynamic>{'t': 'answer', 'sdp': answer.sdp});
      _set(WebrtcPhase.connecting, 'Answer sent to #$_peer; exchanging ICE candidates.');
    } catch (e) {
      await _teardown(sendHangup: false);
      _set(WebrtcPhase.failed, 'Could not accept the call: $e');
    }
  }

  Future<void> _onAnswer(Map<String, dynamic> msg) async {
    final sdp = msg['sdp'] as String?;
    if (_pc == null || sdp == null) return;
    try {
      await _pc!.setRemoteDescription(RTCSessionDescription(sdp, 'answer'));
      _remoteDescriptionSet = true;
      await _flushCandidates();
      _set(WebrtcPhase.connecting, 'Answer received; exchanging ICE candidates.');
    } catch (e) {
      _set(WebrtcPhase.failed, 'Could not apply the answer: $e');
    }
  }

  Future<void> _onCandidate(Map<String, dynamic> msg) async {
    final c = msg['c'] as Map<dynamic, dynamic>?;
    if (c == null) return;
    final candidate = RTCIceCandidate(
      c['candidate'] as String? ?? '',
      c['sdpMid'] as String?,
      c['sdpMLineIndex'] as int?,
    );
    if (_pc == null || !_remoteDescriptionSet) {
      _pendingCandidates.add(<String, dynamic>{
        'c': c,
      });
      return;
    }
    try {
      await _pc!.addCandidate(candidate);
    } catch (_) {
      // A late candidate for a closed ICE generation is harmless.
    }
  }

  Future<void> _flushCandidates() async {
    if (_pc == null || _pendingCandidates.isEmpty) return;
    final queued = List<Map<String, dynamic>>.from(_pendingCandidates);
    _pendingCandidates.clear();
    for (final item in queued) {
      final c = item['c'] as Map<dynamic, dynamic>?;
      if (c == null) continue;
      try {
        await _pc!.addCandidate(RTCIceCandidate(
          c['candidate'] as String? ?? '',
          c['sdpMid'] as String?,
          c['sdpMLineIndex'] as int?,
        ));
      } catch (_) {}
    }
  }

  void _attachRemote(MediaStream stream) {
    _remoteStream = stream;
    remoteRenderer.srcObject = stream;
    if (_phase != WebrtcPhase.connected) {
      _set(WebrtcPhase.connecting, 'Remote track received from #$_peer.');
    }
  }

  void _send(Map<String, dynamic> msg) {
    if (_peer.isEmpty) return;
    _sendTo(_peer, msg);
  }

  void _sendTo(String peer, Map<String, dynamic> msg) {
    final body = <String, dynamic>{...msg, 'peer': relay.myNumber};
    try {
      final frame = 'WRTC|${base64Encode(utf8.encode(jsonEncode(body)))}';
      final sent = relay.sendMessage(peer, frame);
      if (!sent) {
        _set(WebrtcPhase.failed,
            'Signalling could not be sent. Is the relay registered and the peer online?');
      }
    } catch (_) {
      _set(WebrtcPhase.failed, 'Signalling could not be sent. Is the peer still online?');
    }
  }

  Future<void> _teardown({required bool sendHangup}) async {
    final peer = _peer;
    _generation++;
    if (sendHangup && peer.isNotEmpty) {
      _sendTo(peer, <String, dynamic>{'t': 'hangup'});
    }
    final pc = _pc;
    _pc = null;
    _remoteDescriptionSet = false;
    _pendingCandidates.clear();
    try {
      await pc?.close();
      await pc?.dispose();
    } catch (_) {}
    try {
      localRenderer.srcObject = null;
      remoteRenderer.srcObject = null;
    } catch (_) {}
    final local = _localStream;
    final remote = _remoteStream;
    _localStream = null;
    _remoteStream = null;
    try {
      await local?.dispose();
    } catch (_) {}
    try {
      await remote?.dispose();
    } catch (_) {}
    _peer = '';
    _initiator = false;
    _set(WebrtcPhase.idle, 'No active call.');
  }

  void _set(WebrtcPhase phase, String detail) {
    _phase = phase;
    _detail = detail;
    onState?.call(phase, detail);
  }

  Future<void> dispose() async {
    await _teardown(sendHangup: false);
    if (_initialized) {
      await localRenderer.dispose();
      await remoteRenderer.dispose();
      _initialized = false;
    }
  }
}
