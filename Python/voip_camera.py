#!/usr/bin/env python3
"""VoIP video capture helper for USSD Manager Pro.

Reads the webcam (DirectShow), JPEG-compresses each frame and writes
length-prefixed frames to stdout:

    [4-byte little-endian length][JPEG bytes]  (repeated)

The C# app spawns:  python voip_camera.py [width] [height] [fps] [quality]
and reads stdout in a loop, chunking each JPEG into UDP packets.
Ctrl+C / process kill stops capture.
"""
import sys
import time

try:
    import cv2
except ImportError:
    sys.stderr.write("opencv not installed\n")
    sys.exit(2)


def main():
    width = int(sys.argv[1]) if len(sys.argv) > 1 else 320
    height = int(sys.argv[2]) if len(sys.argv) > 2 else 240
    fps = int(sys.argv[3]) if len(sys.argv) > 3 else 12
    quality = int(sys.argv[4]) if len(sys.argv) > 4 else 55

    cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
    if not cap.isOpened():
        sys.stderr.write("camera open failed\n")
        sys.exit(3)
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, width)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, height)
    cap.set(cv2.CAP_PROP_FPS, fps)

    out = sys.stdout.buffer
    interval = 1.0 / max(1, fps)
    try:
        while True:
            t0 = time.time()
            ok, frame = cap.read()
            if not ok:
                break
            ok2, buf = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), quality])
            if not ok2:
                continue
            data = buf.tobytes()
            out.write(len(data).to_bytes(4, "little"))
            out.write(data)
            out.flush()
            dt = time.time() - t0
            if dt < interval:
                time.sleep(interval - dt)
    except BrokenPipeError:
        pass
    finally:
        cap.release()


if __name__ == "__main__":
    main()
