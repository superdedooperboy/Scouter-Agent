# Deploying the Scouter agent with MDM

This directory builds a macOS installer package (`.pkg`) and the Full Disk Access profile you push
through an MDM — Jamf Pro, Kandji, Microsoft Intune, Mosyle, Addigy, or any tool that installs
packages and configuration profiles. For a single Mac you don't need any of this; just run
`sudo python3 agent.py --install-service`. This is for fleets.

Two artifacts go to every managed Mac, and they do different jobs:

| Artifact | What it does | Why MDM must deliver it |
|---|---|---|
| `Scouter-Agent-<ver>.pkg` | Installs the agent, its launcher and its LaunchDaemon, and starts the background service. | An installer can lay down code and a daemon. |
| `Scouter-FullDiskAccess.mobileconfig` | Grants the agent's launcher **Full Disk Access** by code requirement. | Apple reserves Full Disk Access for the user or an MDM — **no installer can grant it.** |

Install the `.pkg` **without** the profile and the agent runs, but read-only with reduced visibility
(it can't read the TCC database, Mail/Messages stores, or receive real-time Endpoint Security events).
Both, and it has the access it needs, with nobody clicking anything.

---

## 1. Build the package

### Testing (unsigned)

```
packaging/build-pkg.sh
```

Writes `packaging/dist/Scouter-Agent-<ver>.pkg`, unsigned. Gatekeeper blocks an unsigned package on a
normal Mac — install it only on a test machine (right-click → Open, or `installer -pkg … -target /`),
or through an MDM configured to install unsigned packages. **Do not ship this to production.**

### Production (signed + notarized)

This is the second pass, once you have an Apple Developer ID (Developer ID Application **and**
Developer ID Installer certificates, and a `notarytool` keychain profile):

```
APP_IDENTITY="Developer ID Application: Your Company (TEAMID)" \
INSTALLER_IDENTITY="Developer ID Installer: Your Company (TEAMID)" \
NOTARY_PROFILE="scouter-notary" \
  packaging/build-pkg.sh
```

- `APP_IDENTITY` signs the **launcher**, giving it a stable identity so the Full Disk Access profile
  survives agent updates (an ad-hoc/unsigned launcher pins the profile to one exact build).
- `INSTALLER_IDENTITY` signs the **package** (required before notarization).
- `NOTARY_PROFILE` is the `xcrun notarytool` keychain profile; with it set, the script submits the
  package for notarization and staples the ticket.

See **Signing and notarization** below to create these once.

## 2. Get the Full Disk Access profile

The profile grants access **by code requirement**, which depends on the launcher's real signature, so
it is generated per build rather than shipped as a static file. On a Mac where you built and installed
the **signed** agent, the installer already wrote it:

```
/Library/Application Support/Scouter/Scouter-FullDiskAccess.mobileconfig
```

Copy that file — it carries the correct bundle identifier and `CodeRequirement`. Upload it to MDM as a
custom configuration profile. (`profiles/Scouter-FullDiskAccess.TEMPLATE.mobileconfig` documents the
shape and a by-hand fill-in path if you'd rather not install first.)

## 3. Push both through your MDM

Order does not matter — install them in whichever order your MDM scopes them; the agent picks up the
grant when the profile lands.

### Jamf Pro
1. **Settings → Computer Management → Packages** → upload `Scouter-Agent-<ver>.pkg`. Add it to a
   **Policy** (trigger: enrollment/recurring check-in), scoped to your fleet.
2. **Computers → Configuration Profiles → New** → **Privacy Preferences Policy Control** payload.
   Either paste the generated profile (**Upload** a custom profile) or add a PPPC entry: App Access
   → `SystemPolicyAllFiles` = **Allow**, identified by the launcher's **bundle ID** and
   **code requirement** (both are in the generated `.mobileconfig`). Scope it to the same fleet.
   > Jamf can also generate a PPPC profile from the uploaded launcher app with **PPPC Utility**.

### Kandji
1. **Library → Add → Custom App** → upload the `.pkg`; set audit/enforcement as you prefer.
2. **Library → Add → PPPC Profile** (or **Custom Profile**) → upload the generated `.mobileconfig`, or
   add a Full Disk Access rule for the launcher bundle ID + code requirement. Assign to a Blueprint.

### Microsoft Intune
1. **Apps → macOS → Add → macOS app (PKG)** → upload the `.pkg`. (Intune's PKG app type requires a
   **signed** package — do the production build first.) Assign to a device group.
2. **Devices → Configuration → Create → Templates → Custom** (or the Settings-catalog PPPC payload) →
   upload the generated `.mobileconfig`. Assign to the same group.

### Mosyle / Addigy / other
Upload the `.pkg` as a managed package and the `.mobileconfig` as a custom configuration profile,
scoped to the same devices. The mechanics differ; the two artifacts and their roles do not.

## 4. Verify

On a managed Mac after both have landed:

```
sudo launchctl print system/com.scouter.agent | head        # daemon loaded + running
sudo python3 "/Library/Application Support/Scouter/agent/agent.py" --service-status
```

The service serves its console on `http://127.0.0.1:8787` (loopback only). The **Sensors** tab reports
whether Full Disk Access and Endpoint Security are active — the honest check that the profile worked.

## Updating and uninstalling

- **Update:** push a newer `.pkg`. The postinstall re-runs `--install-service`, which is idempotent and
  restarts the service on the new code. The Full Disk Access profile keeps working **as long as the
  launcher was Developer ID signed** (stable identity); an ad-hoc launcher needs a fresh profile per
  build, which is why production uses a Developer ID.
- **Uninstall:** `sudo python3 "/Library/Application Support/Scouter/agent/agent.py" --uninstall-service`
  (add `--purge` to also remove collected data), and remove the configuration profile in MDM.

---

## Signing and notarization (one-time setup)

You need an Apple Developer Program membership, then from **Certificates, Identifiers & Profiles**:

1. Create a **Developer ID Application** certificate (signs the launcher) and a **Developer ID
   Installer** certificate (signs the `.pkg`). Install both in your login keychain.
2. Create a notarization credential and store it as a `notarytool` keychain profile:
   ```
   xcrun notarytool store-credentials "scouter-notary" \
     --apple-id "you@example.com" --team-id "TEAMID" --password "APP-SPECIFIC-PASSWORD"
   ```
   (Generate the app-specific password at appleid.apple.com.)
3. Find your identity strings with `security find-identity -v -p codesigning` and
   `security find-identity -v` — use the full `"Developer ID … : Name (TEAMID)"` string.

Then run the production build command in §1. The launcher's stable Developer ID identity is what lets
one Full Disk Access profile cover every update, so sign it with Developer ID before you ship to a
fleet — not ad-hoc.
