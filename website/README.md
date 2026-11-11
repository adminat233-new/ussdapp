# USSD Manager Pro downloads

This repository contains the static download page. It reads the latest published
GitHub release and exposes Windows and Android assets only when those assets are
attached to that release. iOS remains unavailable until an Apple-signed build is
published.

## Deploy on Render

Create a Static Site in Render and connect this repository. The root
[`render.yaml`](../render.yaml) describes the static site for Render Blueprint
deployment. The publish directory is `website/` and no build command is required.

The release workflow at `../.github/workflows/public-test-builds.yml` builds
`UssdApp.exe` and `USSDManager-Android-debug-preview.apk` and attaches them to a
GitHub preview release when a `v*-preview` tag is pushed. The website reads
those release assets and enables direct download buttons; without a published
release, the buttons correctly remain disabled. A release can also be published
manually from the workflow using an existing preview tag.

The supplied video in `assets/ussd-manager-walkthrough.mp4` is the muted,
looping background across the full page. Playback starts automatically when
motion is allowed and pauses while the page is hidden; browsers that block
autoplay retry after the first user interaction. Reduced-motion preferences
pause the background video and scene autoplay. The "How it works" simulation
advances through its scenes automatically with animated transitions and loops
back to the first scene. It is not a live account or a recording of real user
data: the sample user selects a Windows modem, sends a sealed message through a
trusted relay, intentionally shares one phone location, and asks the assistant
a question. Each scene calls out real service requirements and privacy limits.

Do not upload debug builds or signing credentials as public release assets.
