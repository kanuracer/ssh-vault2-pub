# ssh-vault2 RDP Stack

## Goal

ssh-vault2 provides an integrated RDP workspace inside the desktop app. The RDP layer is wrapped behind an internal engine API so UI, session lifecycle, input handling, frame delivery and future protocol work can evolve without changing the user-facing workspace.

## Architecture

```text
Wails AppService
  ↓
rdpstack.Engine
  ↓
RDP session backend
  ↓
Frame sink / input bridge / resize control
  ↓
React + WebGL viewer
```

## Main packages

```text
client/internal/rdpstack
```

Defines backend-neutral contracts:

- `Options`
- `Capabilities`
- `Engine`
- `Session`
- `Sink`
- `Frame`
- `MouseEvent`
- `KeyEvent`

```text
client/internal/rdpstack/native
```

Contains native protocol-building blocks such as:

- TPKT encode/decode
- X.224 connection setup
- MCS/GCC helpers
- NTLM/CredSSP helpers
- transport primitives

```text
client/rdp.go
client/rdp_render.go
client/rdp_control_plane.go
client/frontend/src/rdpWebglRenderer.ts
```

Integrates RDP sessions into the desktop app, including tab lifecycle, control messages, frame parsing and WebGL rendering.

## User-facing behavior

- RDP sessions open as app tabs.
- Sessions use host profile fields for address, port, username, password/domain and display settings.
- Viewer supports scaling modes for different window sizes.
- Keyboard and mouse input are forwarded to the active RDP session.
- Clipboard and file/drop flows are represented at the app workspace layer.

## Development notes

Keep RDP code behind the engine/session contracts. UI code should not depend on backend-specific protocol details. New protocol capabilities should first be represented in `Capabilities`, then wired into the AppService and frontend state.
