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

The "How it works" section is an interactive, silent product-film simulation,
not captured footage or a live connected account. Its sample user walks through
selecting a Windows modem, sending a sealed message through a trusted relay,
intentionally sharing one phone location, and asking the assistant a question.
Scene controls are keyboard-accessible; playback pauses when the page is hidden
and does not auto-start. Each scene calls out real service requirements and
privacy limits.

Do not upload debug builds or signing credentials as public release assets.
