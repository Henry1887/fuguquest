# App-chain (second option): no-adb, fully on-device DirtyFrag → root

This is an **alternative front-end** to the DirtyFrag chain that needs **no adb / no PC / no
wireless-debug pairing**. It drives the exact same kernel primitive (page-cache-poison a carrier
`.ko` → `finit_module` loads the unsigned module → `enforcing=0` + cred-patch) but from a **plain
untrusted_app**, by borrowing capabilities untrusted_app lacks from two *confused-deputy* system
processes.

It does **not** replace or modify the primary chain (`../rust` orchestrator, run via `adb shell
fuguquest` or `--local`). That remains option #1. This folder is option #2.

> Status: the **reachability is proven on Q3** (sepolicy + runtime, build 52433670036000520; see
> "Evidence"). Two steps are engineering-in-progress and flagged **[OPEN]** below. Treat this as a
> validated design + working scaffold, not a turnkey exploit yet.

---

## Why an app can't just run the chain itself

The primary chain needs two triggers that a plain app is SELinux-blocked from:

1. **restart trackingservice** so the injected `init_array` ctor runs and poisons the carrier `.ko`
   + `init.insmod.cfg` (option #1 uses `dumpsys input`, which needs the `DUMP` permission), and
2. **`setprop ctl.start insmod_sh`** to make init `finit_module` the poisoned carrier (option #1 uses
   the `shell` domain; untrusted_app can set **zero** property types).

DirtyFrag itself is the escape: it is *arbitrary code execution in the domain of any process P that
maps (or execs) a file untrusted_app can open read-only, if the app can make P (re)start*. So we use
DirtyFrag to run our own code inside processes that **do** have those capabilities.

## The two deputies (Q3)

| need | deputy process | domain | why it works |
|------|----------------|--------|--------------|
| poison carrier `.ko` + cfg | **trackingservice** | `hal_tracking_default` | maps `libcdsprpc.so` (`same_process_hal_file`, app-readable → poisonable) **and** can read the carrier `vendor_file`. App reaches it (`hal_tracking_default:binder {call,transfer}`). |
| `setprop ctl.start insmod_sh` | **com.oculus.assistant** | `assistant_app` | a `ctl.start_prop` setter; maps `libgralloc.qti.so` (`same_process_hal_file`, app-poisonable); **cold-launchable by a zero-perm app** (exported `MetaAINUXActivity`, `permission=(none)`). |

## Full flow (no adb)

```
untrusted_app:
 1. stage Dirty-Frag SA          (public IpSecManager — allowed: system_server:udp_socket)
 2. build carrier flip.ko + patched cfg + the two ctor stubs   (bundled native `fugu` builder)
 3. page-cache-poison:
      libcdsprpc.so  init_array[0] -> ctor A (poisons carrier .ko + cfg via the SA)   [in trackingservice]
      libgralloc.qti.so init_array[0] -> ctor B (setprop ctl.start insmod_sh)          [in assistant_app]
    (poison done from the app itself: it opens each lib O_RDONLY + sendfile via the SA)
 4. TRIGGER A: restart trackingservice   -> ctor A runs as hal_tracking_default -> carrier+cfg poisoned   [OPEN]
 5. TRIGGER B: startActivity(com.oculus.assistant/.metaai.nux.MetaAINUXActivity)
              -> fresh assistant_app process links libgralloc.qti -> ctor B runs
              -> setprop ctl.start insmod_sh -> init finit_modules the poisoned carrier
 6. kernel: enforcing=0 + cred-patch  (cred carrier target pid = THIS app's pid)
 7. this app's process is now uid 0 + u:r:kernel:s0   (no adb, no Magisk needed as a bridge)
```

Ctor B is functionally the existing `libas-stub` (connect `/dev/socket/property_service`, send a
`SETPROP2` message) but wrapped as an `init_array` ctor that tail-calls the original ctor — with
`ctl`=`ctl.start`, `svc`=`insmod_sh` (instead of `ctl.restart`/`trackingservice`). assistant_app is
allowed the full path: `ctl_start_prop:property_service set`, `property_socket:sock_file write`,
`init:unix_stream_socket connectto` (all verified).

Ctor A is the existing inject-stub (SA-replay poison of carrier+cfg). assistant_app **cannot** read
`vendor_file`, so the carrier `.ko` poison must stay in trackingservice — the assistant is only the
`setprop` deputy.

## Evidence (Q3, build 52433670036000520, from this session)

- `untrusted_app` can open+read `same_process_hal_file`, `system_lib_file`, `vndk_sp_file`,
  `vendor_public_lib_file` (poison sources), and stage the SA (`system_server:udp_socket rw`).
- `ctl_start_prop` setters = `{shell, init, assistant_app, syncboss}`. `syncboss` is dormant +
  app-unreachable; `init` is uninjectable; `shell` needs adb → **`assistant_app` is the only usable one.**
- `com.oculus.assistant` runs in `u:r:assistant_app` (verified by launching it), is **not persistent**,
  and links `libgralloc.qti.so` (+ libgsl/libadreno_utils/…) at startup. `MetaAINUXActivity`,
  `MuxWakeWordPromptActivity`, `AssistantBroadcastReceiver` are **exported, `permission=(none)`**.
- `assistant_app` setprop path fully allowed: `ctl_start_prop:property_service set` +
  `property_socket:sock_file write` + `init:unix_stream_socket connectto`.
- `hal_tracking_default` reads `vendor_file` (carrier) and is app-reachable over binder.

## [OPEN] engineering items

1. **Trigger A — restart trackingservice from untrusted_app.** Option #1 used `dumpsys input`
   (DUMP-gated). Candidates for an app: crash it via a malformed binder transaction to a reachable
   tracking service (`handtracking_service` / `tracking_proxy_service` — the 32-bit asset-truncation
   overflow is a known app-reachable crash), or a legitimate reload trigger. HALs respawn on death →
   ctor A runs on respawn. **Not yet demonstrated.** `Chain.restartTracking()` holds the best-effort.
2. **Ctor B stub bytes.** The `setprop` ctor (property-socket `SETPROP2` + tail-call) is emitted by
   `StubBuilder.assistantSetpropCtor()` — a byte template adapted from `../asm/libas_restart.S.tmpl`.
   Validate the emitted bytes fit `libgralloc.qti`'s init-array code gap and that the ctor runs early.
3. **Shared-page-cache collateral.** `libgralloc.qti` is mapped by many graphics processes; a poisoned
   `init_array` fires ctor B in whatever process next *fresh-links* it. In non-setter domains the
   `setprop` just SELinux-denies (ctor tail-calls orig → benign), but it is noisy: poison → launch the
   assistant immediately → revert the lib fast (like the QPro chain already does with this lib).

## Layout

- `app/` — the untrusted_app APK (no-Gradle build like the repo's other PoCs).
  - `AndroidManifest.xml` — zero dangerous perms (only INTERNET for the loopback SA socket).
  - `src/.../Chain.java` — SA stage + Java poison engine + spec build (bundled `fugu`) + triggers.
  - `src/.../StubBuilder.java` — emits ctor B (assistant setprop stub).
  - `build.sh` — bundles the prebuilt `fugu`, `dfpoison`, `e2e.dex`, `targets/` from the primary
    chain as `assets/`/`jniLibs/` (read-only reuse — the primary chain is not modified).
- `DESIGN.md` — this file.

## Relationship to the primary chain

Reuses, unmodified: `../rust` `fugu` builder subcommands (carrier/cfg/inject-stub/cred-carrier),
`../dfpoison`, `../e2e.dex`, `../targets/*`. Option #1 (adb / `--local`) is unchanged and remains the
recommended, fully-validated path; this is the "install one APK, tap once, no PC" alternative.
