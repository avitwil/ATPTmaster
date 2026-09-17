<p align="center">
  <img src="atpt/assets/logo.png" alt="ATPTmaster" width="320">
</p>

<p align="center"><em>Autonomous Pentest Framework — by Avi Twil</em></p>

# ATPTmaster

A modular, autonomous **penetration-testing framework** for Kali Linux, driven
entirely from a **web console** — or its **desktop app**. Set your scope, connect
an LLM, press **Run**, and watch findings and an attack-direction tree fill in;
download a **PTES-compliant Markdown report** at the end.

- **Two ways to run the UI** — a browser console (`atpt --u`) or a native desktop
  app (`atpt --app`, or the installed icon).
- **Zero-dependency core** — pure Python stdlib; the desktop window adds one
  optional package and gracefully falls back to a browser window without it.
- **Bring your own LLM** — hosted API key, an existing CLI login, or a local
  Ollama. Each operator uses their own keys; nothing proprietary is bundled.

> Only test systems you are **authorized** to test. Every intrusive step enforces
> your engagement scope and, in `semi` mode, pauses for your approval.

## Install

Python ≥ 3.10, stdlib only. **One-line install:**

```bash
curl -fsSL https://raw.githubusercontent.com/avitwil/ATPTmaster/main/bootstrap.sh | bash
```

Or clone it yourself:

```bash
git clone https://github.com/avitwil/ATPTmaster.git atpt && cd atpt && ./install.sh
```

The installer puts an `atpt` launcher on your PATH **and adds an ATPTmaster
desktop icon** to your app grid. Add the optional scanners any time with
`./install.sh --with-tools`.

## Launch the app

```bash
atpt --app     # native desktop window (click the ATPTmaster icon does the same)
atpt --u       # or open the console in your browser → http://127.0.0.1:8787
```

The **desktop app** starts the console on a private local port and opens it in
its own window — no terminal, no browser tab. It stores engagements, uploads and
reports under a per-user data folder (`~/.local/share/ATPTmaster` on Linux,
`~/Library/Application Support/ATPTmaster` on macOS). To build a double-click
installable bundle (Linux binary / macOS `.app`), see
[`packaging/README.md`](packaging/README.md).

Either way you get the same console:

![ATPTmaster console](docs/screenshots/console.png)

The **logo** sits top-right, a **☰ menu** (top-left) holds all settings, **Run**
is top-right, and the body is **chat + status on the left**, **findings +
attack-direction tree on the right**.

## Using the console — a TryHackMe box, end to end

1. **☰ → Scope → Target & scope.** Give it an id and name, put the box IP in
   **Target (IP or CIDR)**, and tick the domains in play (Infra for the IP, Web if
   there's a site). Each domain takes in-scope and out-of-scope lists — the scope
   oracle enforces both before any intrusive tool touches a host.

   ![Scope](docs/screenshots/settings-scope.png)

2. **☰ → Scope → CTF / engagement.** Set the **goals** (injected into the LLM's
   prompts), **pick your `.ovpn`** (a file picker — no path typing), then
   **Connect VPN (background)** to bring the tunnel up. Optionally add an attack-box.

   ![CTF & VPN](docs/screenshots/settings-ctf.png)

3. **☰ → AI settings.** Add a provider (API key, subscription CLI, or Ollama), then
   **☰ → App settings → Model ladder** to order the models to try, each with an
   **effort** level (fetched live in the **Models** panel).

   ![Model ladder](docs/screenshots/settings-ladder.png)

4. **☰ → App settings → Mode**, then press **Run** (top-right). It runs in the
   background — the button becomes **⏸ Pause** / **⏹ Stop** (halt at the next step).
   Findings and the attack tree fill in on the right; grab the report from
   **App settings → Report** (customize per-finding notes and screenshots first).

- **Run / Pause / Stop** — Run executes in the background; **⏸ Pause** and **⏹ Stop**
  halt gracefully at the next module boundary (a running scanner finishes first).
  Intrusive steps still gate on approval in `semi` mode.
- **Chat control** — `run` / `plan` / `status` / `approve <module>` / `report`.
- **Findings** table and an **attack-direction tree** (grouped by domain, ranked
  by severity).

## The ☰ menu

Everything is configured in the menu — no JSON editing:

- **User** — name (appears on the report), company, phone, email.
- **AI settings** — *API providers* (paste a key, stored redacted, or name an env
  var read at call time), *Subscription CLI* (Claude / Gemini / Codex, or a custom
  one, with one-click auto-install), *Local LLM* (Ollama), and *Models* (live-fetched
  per provider; a curated list for the subscription CLIs).
- **Scope** — *Target & scope* (domain-typed: Infra / Web / API / AI / Cloud /
  Mobile / Wireless, each with in/out-of-scope lists) and *CTF / engagement* (VPN
  config, goals, attack-box).
- **App settings** — *Mode* (`step` / `semi` / `full`), *Appearance* (light / dark /
  system, plus **Allow sudo** — password held in memory only), *Model ladder*
  (ordered models each with an effort level), and *Report* (include/exclude findings,
  add notes and screenshots, then **Download**).

Provider / model / user / sudo settings are global; scope, CTF and report settings
attach to the selected engagement.

## Under the hood

The engine, module contract, the 11 shipped capability modules (recon → map →
exploit → validate → report), the scope oracle, and the LLM provider ladder are
documented in [`docs/CORE.md`](docs/CORE.md). Design specs and implementation
plans live under [`docs/superpowers/`](docs/superpowers/). The console binds to
`127.0.0.1` and has no authentication — it's an operator tool, don't expose it.

## License

Licensed under the **Apache License 2.0** — see [`LICENSE`](LICENSE). © 2026 Avi Twil.
Bundled third-party tools under `tools/` retain their own upstream licenses.
