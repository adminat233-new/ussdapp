# USSD Manager Pro downloads

This repository contains the static download page. It reads the latest published
GitHub release and exposes Windows and Android assets only when those assets are
attached to that release. iOS remains unavailable until an Apple-signed build is
published.

## Deploy on Render

Create a Static Site in Render and connect this repository. The included
`render.yaml` also describes the static site for Render Blueprint deployment.
The publish directory is the repository root and no build command is required.

Do not upload debug builds or signing credentials as public release assets.
