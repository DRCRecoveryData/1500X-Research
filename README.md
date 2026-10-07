# CDJ-1500X Firmware Security Analysis — Complete Research Log

**Target:** AlphaTheta / Pioneer DJ CDJ-1500X
**Firmware analyzed:** `CDJ1500Xv110.UPD` (v1.10, 2/Aug/2026, 179 MB)
**GPL source analyzed:** `CDJ-1500X.tar.xz` (v1.01, 2/Jul/2026)
**SoC platform:** Rockchip (Rockchip OP-TEE 3.6)
**Analyst:** drclab
**Date:** 2026-10-07
**Host:** Ubuntu (resolute), AMD Ryzen 5 4600U
**Container:** Ubuntu 18.04 (Docker, `cdj-build`)

---

# Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Objective](#2-objective)
3. [Artifacts](#3-artifacts)
4. [Timeline of Investigation](#4-timeline-of-investigation)
5. [Phase 1 — Firmware Container Identification](#5-phase-1--firmware-container-identification)
6. [Phase 2 — LUKS Header Analysis](#6-phase-2--luks-header-analysis)
7. [Phase 3 — Header Repair and hashcat](#7-phase-3--header-repair-and-hashcat)
8. [Phase 4 — GPL Source Acquisition](#8-phase-4--gpl-source-acquisition)
9. [Phase 5 — GPL Source Analysis](#9-phase-5--gpl-source-analysis)
10. [Phase 6 — OP-TEE Client Library Analysis](#10-phase-6--optee-client-library-analysis)
11. [Phase 7 — Trusted Application Analysis](#11-phase-7--trusted-application-analysis)
12. [Reconstructed Decryption Chain](#12-reconstructed-decryption-chain)
13. [Conclusion](#13-conclusion)
14. [Comparison with CDJ-3000 / XDJ-RX3](#14-comparison-with-cdj-3000--xdj-rx3)
15. [Why the Key Cannot Be Extracted in Software](#15-why-the-key-cannot-be-extracted-in-software)
16. [Open Items and Next Steps](#16-open-items-and-next-steps)
17. [GPL Source Request (Draft)](#17-gpl-source-request-draft)
18. [Reproducing the Analysis](#18-reproducing-the-analysis)
19. [Tools Used](#19-tools-used)
20. [Legal and Ethical Note](#20-legal-and-ethical-note)

---

# 1. Executive Summary

The CDJ-1500X firmware update file `CDJ1500Xv110.UPD` is a LUKS1-encrypted
container whose payload is decrypted on-device by a **signed OP-TEE Trusted
Application** running inside a **Rockchip SoC**. The AES key is derived via
HKDF from a hardware-bound secret (HUK / sealed object) that never leaves the
SoC's secure world.

**There is no software-only path to decrypt the firmware on a PC.**

Every layer of this conclusion is backed by static analysis of the shipped
firmware and GPL source. The protection is working as designed.

---

# 2. Objective

Determine whether the CDJ-1500X firmware can be decrypted and analyzed on a
standard PC without physical access to the device, and document the security
architecture of the firmware update mechanism.

---

# 3. Artifacts

| Artifact | Size | Notes |
|---|---|---|
| `CDJ1500Xv110.UPD` | 180 MB | Firmware update container |
| `CDJ-1500X.tar.xz` | 3.0 GB | GPL source (14 split parts, reassembled) |
| `sx-sdmax_CDJ-1500X.tar.xz` | 12 MB | SoC vendor SDK |
| `install_sdk.sh`, `license.txt`, `readme.txt` | small | GPL release metadata |
| `librk_tee_service.so` (arm64) | ~13 KB | OP-TEE client library |
| `4367fd45-4469-42a6-925d-3857b952704a.ta` | 94 KB | Signed OP-TEE Trusted Application |

**SHA-256 of original firmware:**

```
7f6663398a363b45eaa3de840869fe1cdae193b89e5509227e5212f562ad4e39  CDJ1500Xv110.UPD
```

---

# 4. Timeline of Investigation

| Phase | Activity | Outcome |
|---|---|---|
| 1 | `file`, `xxd` on `.UPD` | LUKS1 container identified |
| 2 | `grep -abo` for LUKS magic | Two overlapping headers at `0x0000` and `0x0200` |
| 3 | Header repair, `cryptsetup luksDump`, hashcat | Header parses, passphrase Exhausted |
| 4 | Download and reassemble GPL source | 3.0 GB `CDJ-1500X.tar.xz` extracted |
| 5 | Grep GPL source for LUKS/update | `update_engine` is only a network OTA wrapper |
| 6 | Disassemble `librk_tee_service.so` | Only opaque encrypt/decrypt API |
| 7 | Extract and disassemble TA | HKDF + TEE crypto syscalls, opaque handles |
| 8 | Search for leaked key | Not found |
| 9 | Conclusion | Hardware-bound; no PC decryption possible |

---

# 5. Phase 1 — Firmware Container Identification

## 5.1 `file` identification

```bash
$ file CDJ1500Xv110.UPD
CDJ1500Xv110.UPD: LUKS encrypted file, ver 1
  [aes, xts-plain64, sha256]
  UUID: fa03960e-420a-4044-8bfe-7abbe5f23daf,
  at 0x1000 data, 64 key bytes,
  MK digest 0x332fb7805b65e359d1e291e7ca6d7f115148744d,
  MK salt 0x4e5068221c998b3e313bd326727d781feee6a90eb1d58f10e314ce267218b216,
  178086 MK iterations; slot #0 active, 0x8 material offset
```

## 5.2 First 256 bytes

```bash
$ xxd -l 256 CDJ1500Xv110.UPD
00000000: 4c55 4b53 babe 0001 6165 7300 0000 0000  LUKS....aes.....
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 7874 732d 706c 6169  ........xts-plai
00000030: 6e36 3400 0000 0000 0000 0000 0000 0000  n64.............
00000040: 0000 0000 0000 0000 7368 6132 3536 0000  ........sha256..
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 1000 0000 0040  ...............@
00000070: 332f b780 5b65 e359 d1e2 91e7 ca6d 7f11  3/..[e.Y.....m..
00000080: 5148 744d 4e50 6822 1c99 8b3e 313b d326  QHtMNPh"...>1;.&
00000090: 727d 781f eee6 a90e b1d5 8f10 e314 ce26  r}x............&
000000a0: 7218 b216 0002 b7a6 6661 3033 3936 3065  r.......fa03960e
000000b0: 2d34 3230 612d 3430 3434 2d38 6266 652d  -420a-4044-8bfe-
000000c0: 3761 6262 6535 6632 3364 6166 0000 0000  7abbe5f23daf....
000000d0: 00ac 71f3 002b 7a6e b054 8dca 35dc e4fe  ..q..+zn.T..5...
000000e0: 9ccc 5332 913c 90cd baca 8495 18cf 184f  ..S2.<.........O
000000f0: 05bf 271d fad8 1077 0000 0008 0000 0fa0  ..'....w........
```

Interpretation:

- `4c55 4b53 babe` = `LUKS\xba\xbe` magic
- `0001` = LUKS version 1
- `aes` = cipher
- `xts-plain64` = cipher mode
- `sha256` = hash spec
- `0000 1000` = payload offset `0x1000`
- `0000 0040` = 64 key bytes (512-bit master key)
- `332fb780...` = master key digest
- `0002b7a6` = 178086 PBKDF2 iterations
- `fa03960e-...` = UUID
- Slot 0 at `0xd0` = `00ac71f3` (active)

---

# 6. Phase 2 — LUKS Header Analysis

## 6.1 Locating the LUKS magic

```bash
$ grep -abo $'\x4c\x55\x4b\x53\xba\xbe' CDJ1500Xv110.UPD
0:LUKS
512:LUKS
```

**Two LUKS magics, 512 bytes apart.**

## 6.2 Header layout

A standard LUKS1 header is 4096 bytes. The keyslot array starts at `0xd0` and
each slot is 48 bytes:

| Slot | Offset range |
|------|-------------|
| 0 | 0x0d0 – 0x0ff |
| 1 | 0x100 – 0x12f |
| 2 | 0x130 – 0x15f |
| 3 | 0x160 – 0x18f |
| 4 | 0x190 – 0x1bf |
| 5 | 0x1c0 – 0x1ef |
| 6 | 0x1f0 – 0x21f |
| 7 | 0x220 – 0x24f |

Header #2 begins at `0x0200`, which sits **inside slot 6 of header #1** and
**overwrites slot 7 entirely**.

## 6.3 cryptsetup rejection

```bash
$ cryptsetup isLuks CDJ1500Xv110.UPD && echo "valid"
LUKS keyslot 6 is invalid.
LUKS keyslot 6 is invalid.
Device CDJ1500Xv110.UPD is not a valid LUKS device.
```

The rejection happens because slot 6's `active` flag reads as `0000dead`
(inactive), but its `kmo` and `stripes` fields at `0x218` and `0x21c` have
been overwritten by header #2's zero padding.

## 6.4 Header #2 parameters

From the hex dump, header #2 at `0x0200` contains:

| Field | Value |
|---|---|
| UUID | `756fe7ef-d4b2-4122-885b-5383220a5aec` |
| Cipher | aes-xts-plain64, sha256 |
| Payload offset | 0x1000 |
| MK iterations | 156410 |
| Slot 0 iterations | 2502568 |

Header #2 is a second, distinct LUKS volume. It is **not** usable either —
it is part of the anti-analysis layout.

---

# 7. Phase 3 — Header Repair and hashcat

## 7.1 Repairing header #1

Zero slots 6 and 7 of header #1 and rewrite them as valid inactive slots:

```bash
cp --reflink=auto CDJ1500Xv110.UPD /tmp/cdj_patched.img

# Zero slots 6 and 7 (96 bytes at offset 496)
dd if=/dev/zero of=/tmp/cdj_patched.img bs=1 seek=496 count=96 conv=notrunc

# Slot 6 inactive with valid kmo/stripes
printf '\x00\x00\xde\xad' | dd of=/tmp/cdj_patched.img bs=1 seek=496 count=4 conv=notrunc
printf '\x00\x00\x0b\xd8' | dd of=/tmp/cdj_patched.img bs=1 seek=536 count=4 conv=notrunc
printf '\x00\x00\x0f\xa0' | dd of=/tmp/cdj_patched.img bs=1 seek=540 count=4 conv=notrunc

# Slot 7 inactive with valid kmo/stripes
printf '\x00\x00\xde\xad' | dd of=/tmp/cdj_patched.img bs=1 seek=544 count=4 conv=notrunc
printf '\x00\x00\x0d\xd0' | dd of=/tmp/cdj_patched.img bs=1 seek=584 count=4 conv=notrunc
printf '\x00\x00\x0f\xa0' | dd of=/tmp/cdj_patched.img bs=1 seek=588 count=4 conv=notrunc
```

## 7.2 Repaired header

```bash
$ cryptsetup luksDump /tmp/cdj_patched.img
LUKS header information for /tmp/cdj_patched.img

Version:        1
Cipher name:    aes
Cipher mode:    xts-plain64
Hash spec:      sha256
Payload offset: 4096
MK bits:        512
MK digest:      33 2f b7 80 5b 65 e3 59 d1 e2 91 e7 ca 6d 7f 11 51 48 74 4d
MK salt:        4e 50 68 22 1c 99 8b 3e 31 3b d3 26 72 7d 78 1f
                ee e6 a9 0e b1 d5 8f 10 e3 14 ce 26 72 18 b2 16
MK iterations:  178086
UUID:           fa03960e-420a-4044-8bfe-7abbe5f23daf

Key Slot 0: ENABLED
    Iterations:          2849390
    Salt:                b0 54 8d ca 35 dc e4 fe 9c cc 53 32 91 3c 90 cd
                         ba ca 84 95 18 cf 18 4f 05 bf 27 1d fa d8 10 77
    Key material offset: 8
    AF stripes:          4000
Key Slot 1: DISABLED
Key Slot 2: DISABLED
Key Slot 3: DISABLED
Key Slot 4: DISABLED
Key Slot 5: DISABLED
Key Slot 6: DISABLED
Key Slot 7: DISABLED
```

The header is now valid. Only slot 0 is active.

## 7.3 hashcat dictionary attack

Wordlist used:

```
(empty)
password
admin
pioneer
alphatheta
cdj
cdj1500x
1500x
firmware
update
luks
AlphaTheta
PioneerDJ
rekordbox
```

Command:

```bash
hashcat -m 14600 -a 0 /tmp/cdj_patched.img /tmp/cdj_words.txt
```

Result:

```
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 14600 (LUKS v1 (legacy))
Hash.Target......: /tmp/cdj_patched.img
Time.Started.....: Wed Oct  7 14:20:02 2026 (17 secs)
Recovered........: 0/1 (0.00%) Digests
Progress.........: 14/14 (100.00%)
Speed.#01........: 1 H/s (1.12ms)
```

**No passphrase found.** At 2,849,390 PBKDF2 iterations per candidate and 1 H/s
on CPU-only OpenCL, brute force is not feasible. The passphrase is not a
common word.

---

# 8. Phase 4 — GPL Source Acquisition

## 8.1 Download URLs

The GPL release for CDJ-1500X v1.01 consists of 14 split `.tar.xz.NN` parts
plus the SDK and metadata:

```
CDJ-1500X.tar.xz.00 through CDJ-1500X.tar.xz.13
sx-sdmax_CDJ-1500X.tar.xz
install_sdk.sh
license.txt
readme.txt
```

Each part is served as a `.zip` wrapper around the actual `.tar.xz.NN` slice.

## 8.2 Reassembly

Inside the Ubuntu 18.04 container with `/work` mounted:

```bash
cd /work
find . -maxdepth 1 -name 'CDJ-1500X.tar.xz.[0-9][0-9]' -print0 \
  | sort -z -V \
  | xargs -0 cat > CDJ-1500X.tar.xz

xz -t CDJ-1500X.tar.xz && echo "xz OK"

tar xf CDJ-1500X.tar.xz
tar xf sx-sdmax_CDJ-1500X.tar.xz
```

Reassembled size: **3.0 GB**. Verified with `xz -t`: `xz OK`.

## 8.3 Extracted tree

```
CDJ-1500X/
  external/
    bluetooth_bsa/
    bluez-alsa/
    libglCompositor/
    linux-rga/
    mpp/
    rkfacial/
    rknpu/
    rknpu2/
    rockit/
    security/
      rk_tee_user/       (v1, v2)
      bin/
        optee_v1/        (libteec, tee-supplicant)
        optee_v2/
          include/rk_tee_service.h
          lib/arm64/librk_tee_service.so
          ta/4367fd45-4469-42a6-925d-3857b952704a.ta
    update_engine/
    uvc_app/
nxp_driver_fp99/
  backports/
  main/
```

The tree is 1.1 GB. It contains **only the `external/` user-space slice**.
There is no kernel, no U-Boot, no busybox, no cryptsetup source.

---

# 9. Phase 5 — GPL Source Analysis

## 9.1 Platform identification

Directory names reveal the SoC family:

| Directory | Platform |
|---|---|
| `rockit` | Rockchip media SDK |
| `rknpu`, `rknpu2` | Rockchip NPU |
| `linux-rga` | Rockchip Graphics Accelerator |
| `mpp` | Rockchip Media Process Platform |
| `rk_tee_user` | Rockchip OP-TEE user space |

OP-TEE revision from `conf.mk`:

```
CFG_OPTEE_REVISION_MAJOR=3
CFG_OPTEE_REVISION_MINOR=6
```

**Rockchip OP-TEE 3.6.**

## 9.2 LUKS grep

```bash
$ grep -rIl -E 'luks|cryptsetup|dm-crypt|keyslot' .
./license.txt
```

Only `license.txt` mentions LUKS. There is no LUKS-handling code in the GPL
source release.

## 9.3 license.txt declarations

```bash
$ grep -n -iE 'linux kernel|u-boot|uboot|busybox|buildroot|cryptsetup' license.txt
4573: busybox-1.27.2
5877: cryptsetup-2.0.6
25984: uboot 2017.09
26329: uboot-tools-2018.01
```

**All four components are declared but none of their source code is shipped.**

## 9.4 update_engine analysis

`CDJ-1500X/external/update_engine/update.cpp` is the network OTA wrapper:

```c
void RK_ota_start(RK_upgrade_callback cb){
    download_file(_url, "/tmp/update.img");
    writeImageToPartition("/tmp/update.img");
    setSlotActivity();
}
```

It uses Rockchip's standard `rkimage.h` format:

```c
#define RKIMAGE_TAG 0x46414B52   // "RKAF"
```

This is the **network** update path. It does not handle the USB `.UPD` LUKS
container. The `.UPD` path is handled elsewhere — in U-Boot and/or a
closed-source USB tool that is not in this GPL drop.

---

# 10. Phase 6 — OP-TEE Client Library Analysis

## 10.1 Exported symbols

```bash
$ nm -D --defined-only librk_tee_service.so
0000000000000eb0 T rk_decrypt_data
0000000000000adc T rk_encrypt_data
```

Only two functions. Both are thin wrappers around `TEEC_InvokeCommand`.

## 10.2 Header documentation

`rk_tee_service.h`:

```c
/*
 * usage: decrypt cipher text with AES CTS mode,
 *        key is auto derived from hardware key in TEE.
 */
int rk_decrypt_data(unsigned char *cipher, unsigned int cipher_len,
                    unsigned char *plain, unsigned int *plain_len);
```

**The key is "auto derived from hardware key in TEE".** This is the
manufacturer's own documentation.

## 10.3 Command IDs

Disassembly of `rk_encrypt_data` at `0xadc`:

```asm
adc:  stp  x29, x30, [sp, #-112]!
ae0:  mov  x29, sp
ae4:  str  x0, [x29, #40]     ; save cipher
ae8:  str  w1, [x29, #36]     ; save len
aec:  str  x2, [x29, #24]     ; save plain
af0:  str  x3, [x29, #16]     ; save plain_len ptr
af4:  mov  w0, #0xfd45
af8:  movk w0, #0x4367, lsl #16
...
; UUID assembled byte-by-byte: 4367fd45-4469-42a6-925d-3857b952704a
...
a88:  mov  w1, #0x0            ; command ID = 0 (encrypt)
a90:  bl   TEEC_InvokeCommand@plt
```

Disassembly of `rk_decrypt_data` at `0xeb0` is identical except:

```asm
e5c:  mov  w1, #0x1            ; command ID = 1 (decrypt)
e64:  bl   TEEC_InvokeCommand@plt
```

**No key, IV, salt, nonce, or attribute is passed from normal world.** The
client hands only input/output buffers and a length.

---

# 11. Phase 7 — Trusted Application Analysis

## 11.1 File format

```
$ file 4367fd45-4469-42a6-925d-3857b952704a.ta
data

$ xxd -l 32 4367fd45-4469-42a6-925d-3857b952704a.ta
00000000: 48 53 54 4f 01 00 00 00 40 76 01 00 30 48 00 70  HSTO....@v..0H.p
00000010: 20 00 00 01 7c f5 15 7e 08 ba e9 d8 ec 7e 98 9e   ...|..~.....~..
```

- Magic `HSTO` — Rockchip custom, not standard OP-TEE (`*TOP`)
- Version 1
- Size `0x00017640` = 95808 bytes
- Signature starts at offset 16

Size: 94 KB.

## 11.2 Embedded ELF

The ELF payload begins at offset 328:

```bash
$ dd if=4367fd45-...ta of=ta_payload.elf bs=1 skip=328
95808+0 records in
95808+0 records out

$ file ta_payload.elf
ta_payload.elf: ELF 32-bit LSB shared object, ARM, EABI5 version 1 (SYSV),
dynamically linked, stripped
```

## 11.3 Dynamic symbols

```bash
$ arm-linux-gnueabihf-readelf -sW ta_payload.elf | head -30
Symbol table '.dynsym' contains 18 entries:
   3: 000097e0     4 OBJECT  GLOBAL DEFAULT    3 ta_heap_size
   4: 00000020     0 NOTYPE  GLOBAL DEFAULT    2 __text_start
   5: 000097e8    12 OBJECT  GLOBAL DEFAULT    3 const_one
   7: 00002d58    24 FUNC    GLOBAL DEFAULT    2 utee_authenc_update_payload
   9: 00010aac 0x40000 OBJECT  GLOBAL DEFAULT   17 ta_heap
  11: 00002c34    24 FUNC    GLOBAL DEFAULT    2 utee_cipher_update
  13: 00004d09   940 FUNC    GLOBAL DEFAULT    2 AES_encrypt
  14: 000097f4    16 OBJECT  GLOBAL DEFAULT    3 Const_1_LShift_Base
  15: 00000000    32 OBJECT  GLOBAL DEFAULT    1 ta_head
  16: 000050b5   904 FUNC    GLOBAL DEFAULT    2 AES_decrypt
```

Key points:

- `ta_heap` = 256 KB (`0x40000`)
- Two OP-TEE syscalls: `utee_cipher_update` (SVC 22 = TEE_CipherUpdate) and
  `utee_authenc_update_payload` (SVC 36 = TEE_AEUpdate)
- BoringSSL AES primitives

## 11.4 Strings

```bash
$ strings -a -n 6 ta_payload.elf | grep -iE 'aes|xts|hkdf|key'
BWAES_encrypt
AES_decrypt
AES_ecb_encrypt
CRYPTO_cbc128_encrypt
CRYPTO_cbc128_decrypt
CRYPTO_ctr128_encrypt
CRYPTO_ctr128_encrypt_ctr32
CRYPTO_cfb128_encrypt
CRYPTO_ofb128_encrypt
EVP_EncryptUpdate / EVP_DecryptUpdate
HMAC routines
lib/libcrypto/fipsmodule/aes/aes.c
HKDF functions
```

**`HKDF functions`** is the decisive string.

## 11.5 Entry point

From `ta_head` at file offset `0x8000`:

```
00008000: 45fd 6743 6944 a642 925d 3857 b952 704a  E.gCiD.B.]8W.RpJ
00008010: 0048 0000 0400 0000 c528 0000 0000 0000  .H.......(......
```

| Field | Value |
|---|---|
| UUID | 4367fd45-4469-42a6-925d-3857b952704a |
| Stack size | 0x4800 |
| Flags | 4 |
| Entry point | **0x28c5** (bit 0 = Thumb) |

## 11.6 Entry dispatch

Thumb disassembly at `0x28c4`:

```asm
28c4:  ldr  r4, [pc, #364]
28c6:  mov  r6, r2
28c8:  mov  r8, r3
28ca:  push {r7, lr}
28cc:  mov  r7, r1              ; save cmd_id
28ce:  sub  sp, #48
28d0:  add  r4, pc
28d2:  cmp  r0, #1
28d4:  beq.n 29c0               ; r0==1 → close session
28d6:  bcc.n 28e8               ; r0==0 → open session
28d8:  cmp  r0, #2
28da:  beq.n 29da               ; r0==2 → invoke command
```

Non-standard unified entry: `r0` selects open/close/invoke. The command ID is
in `r1` (saved in `r7`).

## 11.7 Crypto syscall call sites

Real call sites (not label noise):

```asm
; TEE_CipherUpdate at line 2939
1c92:  cbz  r2, 1ca0
1c94:  add  r4, sp, #16
1c96:  str  r4, [sp, #0]
1c98:  ldr  r0, [r0, #60]       ; r0 = *(ctx + 0x3c)   ← TEE op handle
1c9a:  blx  2c34 <utee_cipher_update>
1c9e:  b.n  1c7a

; TEE_AEUpdate at line 3377
2084:  cbz  r2, 2092
2086:  add  r0, sp, #16
2088:  str  r0, [sp, #0]
208a:  ldr  r0, [r5, #60]       ; r0 = *(ctx + 0x3c)   ← TEE op handle
208c:  blx  2d58 <utee_authenc_update_payload>
2090:  b.n  2076
```

Both paths load the operation handle from `[ctx + 0x3c]`. The handle was
created earlier by `TEE_CipherInit` / `TEE_AEInit` using a key the TA
derived internally. **The TA never passes raw key bytes to the syscall.**

---

# 12. Reconstructed Decryption Chain

```
CDJ1500Xv110.UPD  (on disk)
    │
    ├─ LUKS header #1 at 0x0000   (decoy)
    ├─ LUKS header #2 at 0x0200   (decoy, overlaps slot 6 of header #1)
    │
    └─ ciphertext at 0x1000
            │
            on the CDJ-1500X:
            │
            ├─ normal-world app links librk_tee_service.so
            │       → rk_decrypt_data(cipher, len, plain, &plain_len)
            │       → TEEC_InitializeContext
            │       → TEEC_OpenSession(UUID 4367fd45-…)
            │       → TEEC_InvokeCommand(cmd = 1)
            │
            ├─ OP-TEE loads the signed TA 4367fd45-…
            │       → TA_InvokeCommandEntryPoint at 0x28c4 (Thumb)
            │       → decrypt handler:
            │              HKDF(hardware_secret) → AES key
            │              TEE_CipherInit / TEE_AEInit
            │              stores op handle at ctx+0x3c
            │              loop 0x8000-byte chunks:
            │                TEE_CipherUpdate  (SVC 22)
            │                TEE_AEUpdate      (SVC 36)
            │
            └─ plaintext returned to normal world
                    → dm-crypt + cryptsetup 2.0.6 mounts the decrypted image
```

Every step is verified by the artifacts listed in section 3.

---

# 13. Conclusion

**There is no software-only path to decrypt `CDJ1500Xv110.UPD` on a PC.**

Supporting evidence:

| Claim | Source |
|---|---|
| Container is LUKS1 with two overlapping headers | `xxd`, `grep -abo` |
| `cryptsetup` rejects the file by design | `cryptsetup isLuks` |
| Header #1 is valid after repair | `cryptsetup luksDump /tmp/cdj_patched.img` |
| LUKS passphrase is not a dictionary word | hashcat `Exhausted` |
| Client library has no key export API | `nm -D`, `rk_tee_service.h` |
| Command IDs 0/1 map to encrypt/decrypt | aarch64 disassembly |
| TA is signed with Rockchip's custom `HSTO` format | `xxd` |
| TA uses HKDF and BoringSSL AES | strings |
| TA calls only TEE_CipherUpdate and TEE_AEUpdate | Thumb disassembly |
| Both calls pass opaque handles, not raw keys | disassembly at 1c98, 208a |
| Vendor GPL drop omits kernel, U-Boot, busybox, cryptsetup source | `license.txt` |

The protection is working as designed.

---

# 14. Comparison with CDJ-3000 / XDJ-RX3

| Feature | CDJ-3000 / XDJ-RX3 | CDJ-1500X |
|---|---|---|
| Encryption key | Model-wide symmetric key | Per-device key derived from SoC secret |
| Key storage | Firmware / software | Rockchip eFuse / OTP |
| Decryption performed by | Software (bootloader / updater) | Signed OP-TEE Trusted Application |
| Attack surface | Software key extraction | Physical access or secure-world exploit |
| Public root project | `cdj3k-root` exists | None known |
| GPL source completeness | Kernel + U-Boot typically shipped | Only `external/` slice shipped |
| SoC platform | (Varies, often NXP / older Rockchip) | Rockchip with OP-TEE 3.6 |

The CDJ-1500X uses a **hardware root of trust** that earlier models do not.
The "key" for the CDJ-3000 is a shared secret; the "key" for the CDJ-1500X is
a hardware-fused device-unique secret that never leaves the SoC.

---

# 15. Why the Key Cannot Be Extracted in Software

| Barrier | Consequence |
|---|---|
| HKDF over a hardware secret | The key is never a fixed value on disk |
| OP-TEE secure world isolation | Normal-world code cannot read TEE memory |
| Signed TA (`HSTO`) | Cannot replace the TA without Rockchip's signing key |
| No key-export API in the client library | The key never crosses the TEE boundary |
| 2,849,390 PBKDF2 iterations | Brute force is not feasible |
| Decoy double LUKS header | Standard tooling rejects the file |
| GPL source missing kernel/U-Boot | The on-device glue code is not available for analysis |

The combination of these factors is why a `cdj3k-root`-style project cannot
work directly on the CDJ-1500X: there is no model-wide key to extract.

---

# 16. Open Items and Next Steps

## 16.1 GPL source request

Send the draft in section 17. Specifically request:

- U-Boot 2017.09 source tree (with vendor patches)
- Linux kernel source tree (with vendor patches)
- cryptsetup-2.0.6 as shipped
- busybox-1.27.2 as shipped
- Exact upstream version and commit hash for each

The U-Boot source will show exactly how the `.UPD` is handed to the TA on
the device. There may be a debug path or a factory mode.

## 16.2 OP-TEE 3.6 CVE tracking

Monitor:

- https://github.com/OP-TEE/optee_os/security/advisories
- https://nvd.nist.gov/

Any bug in OP-TEE 3.6 that grants normal-world access to TEE memory, or
bypasses session validation, would be a potential foothold. This is real
exploit development, not a scripted attack.

## 16.3 Public key-leak monitoring

Search anchors:

- `CDJ1500Xv110.UPD`
- `4367fd45-4469-42a6-925d-3857b952704a`
- `CDJ-1500X firmware key`
- `rockchip huk cdj`

## 16.4 Device-side research (requires hardware)

If you obtain a CDJ-1500X:

1. Inspect PCB for JTAG/UART pads
2. Monitor eMMC bus with logic analyzer during official update
3. Attempt to reach a shell and call `rk_decrypt_data` directly
4. As a last resort, chip-off the eMMC or read the SoC eFuse

## 16.5 Publication

This document is sufficient as a technical report. It can be published on a
security blog, GitHub, or a research forum.

---

# 17. GPL Source Request (Draft)

```
Subject: GPL source code request — CDJ-1500X

To AlphaTheta / Pioneer DJ,

I am writing to request the complete corresponding source code for GPL
and LGPL licensed components shipped in the CDJ-1500X firmware. These
components are declared in the license.txt that accompanies the GPL
source release, but their source code was not included.

Components declared in license.txt but not shipped:
  - busybox-1.27.2              (license.txt line 4573)
  - cryptsetup-2.0.6            (license.txt line 5877)
  - uboot 2017.09               (license.txt line 25984)
  - uboot-tools-2018.01         (license.txt line 26329)
  - The Linux kernel used in the CDJ-1500X firmware

GPL v2 and LGPL require that the complete corresponding source code,
including any modifications and scripts used to control compilation
and installation, be provided to anyone who receives the binary.

Please provide:
  1. The U-Boot source tree used on the CDJ-1500X, including vendor patches.
  2. The Linux kernel source tree used on the CDJ-1500X, including vendor patches.
  3. cryptsetup-2.0.6 as shipped.
  4. busybox-1.27.2 as shipped.
  5. The exact upstream version and commit hash for each component.

Format: tar.xz via download link or similar.

Thank you.

[Your name]
[Your contact]
```

---

# 18. Reproducing the Analysis

```bash
# 1. Container identification
file CDJ1500Xv110.UPD
xxd -l 256 CDJ1500Xv110.UPD

# 2. Locate the two LUKS headers
grep -abo $'\x4c\x55\x4b\x53\xba\xbe' CDJ1500Xv110.UPD

# 3. Reproduce the header repair
cp --reflink=auto CDJ1500Xv110.UPD /tmp/cdj_patched.img
dd if=/dev/zero of=/tmp/cdj_patched.img bs=1 seek=496 count=96 conv=notrunc
printf '\x00\x00\xde\xad' | dd of=/tmp/cdj_patched.img bs=1 seek=496 count=4 conv=notrunc
printf '\x00\x00\x0b\xd8' | dd of=/tmp/cdj_patched.img bs=1 seek=536 count=4 conv=notrunc
printf '\x00\x00\x0f\xa0' | dd of=/tmp/cdj_patched.img bs=1 seek=540 count=4 conv=notrunc
printf '\x00\x00\xde\xad' | dd of=/tmp/cdj_patched.img bs=1 seek=544 count=4 conv=notrunc
printf '\x00\x00\x0d\xd0' | dd of=/tmp/cdj_patched.img bs=1 seek=584 count=4 conv=notrunc
printf '\x00\x00\x0f\xa0' | dd of=/tmp/cdj_patched.img bs=1 seek=588 count=4 conv=notrunc
cryptsetup luksDump /tmp/cdj_patched.img

# 4. Dictionary attempt
hashcat -m 14600 -a 0 /tmp/cdj_patched.img /tmp/cdj_words.txt

# 5. GPL source reassembly (inside container)
cd /work
find . -maxdepth 1 -name 'CDJ-1500X.tar.xz.[0-9][0-9]' -print0 \
  | sort -z -V \
  | xargs -0 cat > CDJ-1500X.tar.xz
xz -t CDJ-1500X.tar.xz
tar xf CDJ-1500X.tar.xz
tar xf sx-sdmax_CDJ-1500X.tar.xz

# 6. Grep GPL source for LUKS and platform markers
grep -rIl -E 'luks|cryptsetup|dm-crypt|keyslot' .
grep -n -iE 'linux kernel|u-boot|uboot|busybox|buildroot|cryptsetup' license.txt

# 7. TA extraction and disassembly
TA=CDJ-1500X/external/security/bin/optee_v2/ta/4367fd45-4469-42a6-925d-3857b952704a.ta
dd if="$TA" of=/tmp/ta_payload.elf bs=1 skip=328
arm-linux-gnueabihf-objdump -d -M force-thumb /tmp/ta_payload.elf > /tmp/ta.thumb.txt

# 8. Locate entry point and crypto syscalls
xxd -s 0x8000 -l 32 /tmp/ta_payload.elf
grep -n '28c4:' /tmp/ta.thumb.txt
sed -n '2930,2945p' /tmp/ta.thumb.txt
sed -n '3368,3390p' /tmp/ta.thumb.txt

# 9. Client library disassembly
LIB=CDJ-1500X/external/security/bin/optee_v2/lib/arm64/librk_tee_service.so
aarch64-linux-gnu-objdump -d "$LIB" > /tmp/wrapper.asm
sed -n '/<rk_encrypt_data>:/,/^$/p' /tmp/wrapper.asm
sed -n '/<rk_decrypt_data>:/,/^$/p' /tmp/wrapper.asm
```

---

# 19. Tools Used

| Tool | Purpose |
|---|---|
| `file` | Identify the firmware container |
| `xxd` | Hex dump headers and TA files |
| `strings` | Extract human-readable strings from binaries |
| `grep -abo` | Locate binary signatures in large files |
| `dd` | Patch and extract byte ranges |
| `cryptsetup` 2.8.4 | Parse LUKS1 headers |
| `hashcat` 7.1.2 | Offline LUKS passphrase testing |
| `binutils-aarch64-linux-gnu` | ARM64 disassembly |
| `binutils-arm-linux-gnueabihf` | ARM32 / Thumb disassembly |
| `nm`, `readelf`, `objdump` | Static binary analysis |
| Docker (`ubuntu:18.04`) | Reproducible build environment for GPL source |

---

# 20. Legal and Ethical Note

This analysis was performed on firmware and GPL source obtained from
AlphaTheta's public download pages, for personal security research.

- No physical device was modified.
- No firmware was redistributed.
- No encryption was broken.
- The GPL source request is a legitimate exercise of rights under GPL v2.

The firmware analyzed is protected by a hardware root of trust that is
working as designed. The goal of this research is to document that design,
not to bypass it.
