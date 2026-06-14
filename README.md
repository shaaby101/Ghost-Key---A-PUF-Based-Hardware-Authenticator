# GhostKey 
### PUF-Based Hardware Security Authentication System

GhostKey is a hardware authentication system built on an **Arduino Uno** and **ESP32** that uses a *Physical Unclonable Function (PUF)* — a cryptographic fingerprint derived from the physical imperfections of the Arduino's silicon — to verify that a piece of hardware is exactly who it claims to be. It also features three layers of tamper detection that automatically destroy the authentication database if anyone tries to open, probe, or attack the device.

> **This is a hardware security project**, not a user login system. GhostKey answers the question: *"Is this the exact same Arduino that was originally enrolled?"* — not *"Is this the right person?"* Understanding this distinction is the key to understanding the whole project.

---

## Table of Contents

1. [How It Works — The Big Picture](#1-how-it-works--the-big-picture)
2. [Core Concepts Explained](#2-core-concepts-explained)
   - [Physical Unclonable Function (PUF)](#21-physical-unclonable-function-puf)
   - [Challenge-Response Authentication](#22-challenge-response-authentication)
   - [Tamper Detection (Three Layers)](#23-tamper-detection-three-layers)
   - [Hardware Root of Trust](#24-hardware-root-of-trust)
3. [System Architecture](#3-system-architecture)
4. [The Key Lifecycle](#4-the-key-lifecycle)
   - [Phase 1 — Enrollment](#phase-1--enrollment-done-once)
   - [Phase 2 — Authentication](#phase-2--authentication-every-access-attempt)
   - [Phase 3 — Tamper Event](#phase-3--tamper-event)
   - [De-enrollment & Re-enrollment](#de-enrollment--re-enrollment)
5. [Hardware & Wiring](#5-hardware--wiring)
   - [Components List](#components-list)
   - [Wiring Diagram](#wiring-diagram)
   - [Logic Level Shifting](#logic-level-shifting)
6. [Software Overview](#6-software-overview)
   - [Arduino Firmware](#arduino-firmware-arduino_unoino)
   - [ESP32 Firmware](#esp32-firmware-esp_32ino)
7. [Getting Started](#7-getting-started)
8. [Calibration & Tuning](#8-calibration--tuning)
9. [Honest Limitations](#9-honest-limitations)
10. [Real-World Applications](#10-real-world-applications)
11. [Frequently Asked Questions](#11-frequently-asked-questions)

---

## 1. How It Works — The Big Picture

Imagine a lock that recognises not your key's shape, but the microscopic atomic imperfections in the metal it was cast from — imperfections that are physically impossible to copy, even with the original mould. That is what GhostKey does, in silicon.

**The two-board setup:**

| Board | Role | Analogy |
|---|---|---|
| **Arduino Uno** | The *key* — its silicon fingerprint is the credential | A physical key |
| **ESP32** | The *lock* — verifies the key, controls the relay, monitors for tampering | A smart lock with a camera |

**The flow, in plain English:**

1. You press a button on the outside of a sealed box.
2. The ESP32 (inside the box) generates a random number and sends it to the Arduino (also inside the box).
3. The Arduino mixes that random number with its unique physical fingerprint and sends back a response.
4. The ESP32 independently calculates what the response *should* be, based on the fingerprint it recorded during enrollment.
5. If the two match closely enough → the relay opens the lock. Green LED.
6. If they don't → access denied. Red LED.
7. If anyone opens the box, tampers with it, or tries a voltage glitch attack → the database of fingerprints is instantly wiped. The lock closes permanently until an administrator re-enrolls.

---

## 2. Core Concepts Explained

### 2.1 Physical Unclonable Function (PUF)

When you manufacture a silicon chip, tiny, random imperfections emerge at the atomic level — microscopic variations in resistance, gate delays, and capacitance. No two chips are identical in this way, even if they come from the same factory run. These imperfections can be measured and used as a unique, unclonable fingerprint.

**GhostKey uses an SRAM PUF.** When the Arduino Uno powers on, its SRAM memory cells (before any firmware initialises them) settle into a random pattern of 1s and 0s. This pattern is determined entirely by the physical imperfections of that specific chip. It is *repeatable* — power the same chip on a hundred times and you get the same (or very nearly the same) pattern every time. Power a *different* chip on and you get a completely different pattern.

```
Power-on SRAM snapshot → Physical fingerprint → The "key"
```

**Why it cannot be cloned:** To copy the PUF, an attacker would need to replicate atomic-level manufacturing variations. This is physically impossible — even the original chip manufacturer cannot produce a second identical chip.

**Why fuzzy matching is necessary:** The SRAM pattern is not pixel-perfectly stable across different temperatures and supply voltages. A few bits may flip between power cycles. GhostKey therefore uses *Hamming distance* (a count of how many bits differ) with a tolerance threshold, rather than demanding an exact match. This is handled in the firmware automatically.

---

### 2.2 Challenge-Response Authentication

A challenge-response protocol is how GhostKey avoids the most common attack on wired communication: **replay attacks**, where an eavesdropper records a valid message and plays it back later.

The protocol works like this:

```
ESP32 → "Here is a random 64-byte number" (the challenge) → Arduino
Arduino → mixes challenge with its PUF fingerprint → computes a response
Arduino → "Here is my response" → ESP32
ESP32 → derives the expected response independently → compares
```

Because the challenge is **randomly generated from hardware entropy every single time**, an attacker who wiretaps the UART line between the two boards captures a response that is useless — the next authentication round uses a completely different challenge.

**The mixing algorithm** (in `derive_response()` on the Arduino and mirrored in `derive_expected_response()` on the ESP32) combines the challenge with the PUF fingerprint using XOR and a non-linear rolling hash. This ensures:
- The raw PUF fingerprint is never transmitted on the wire.
- Each authentication produces a unique (challenge, response) pair.
- Collecting many (challenge, response) pairs does not practically recover the PUF fingerprint.

> A production system would use HMAC-SHA256 for the mixing step. The bare Arduino Uno lacks a hardware crypto accelerator and the flash space for a full SHA library, so a custom rolling XOR-hash is used instead.

---

### 2.3 Tamper Detection (Three Layers)

The sealed enclosure is protected by three independent tamper sensors. **Any one of them triggering causes the ESP32 to immediately wipe its enrolled PUF database from flash memory.** Without that database, the system cannot verify anything and locks permanently.

| Layer | Sensor | What It Detects |
|---|---|---|
| **Light** | LDR (Light Dependent Resistor) | The enclosure being opened — ambient light floods in |
| **Vibration** | SW-420 Module | Physical probing, drilling, or rough handling |
| **Voltage** | LM393 Comparator | Voltage glitching attacks on the power rail |

**What gets wiped vs. what stays:**

Think of a nightclub bouncer:
- The **firmware** is the bouncer. He stays. The ESP32 doesn't become a brick.
- The **enrolled PUF profile** is the guest list. That gets shredded on tamper.

Without the guest list, the bouncer won't let *anyone* in — not even the legitimate Arduino — until an authorised administrator physically re-enrolls the system.

**Voltage glitching** deserves a specific note: this is a real hardware attack technique used against embedded systems. An attacker injects a brief, precise voltage spike to cause the processor to skip instructions — potentially bypassing an `if (authenticated)` check. GhostKey's comparator circuit monitors the power rail and triggers a tamper event if it detects any anomaly before such an attack can succeed.

---

### 2.4 Hardware Root of Trust

Software security is always only as strong as the hardware it runs on — a sufficiently privileged attacker can modify software. A **Hardware Root of Trust** grounds security in a layer that is physically difficult to tamper with.

GhostKey uses two ESP32 hardware security features for this:

- **eFuses**: One-time-programmable memory cells that store cryptographic keys. Once written, they cannot be read back through software or changed. They are physically burned into the chip.
- **Flash Encryption**: Encrypts the ESP32's flash storage. If an attacker removes and reads the flash chip with external hardware, all they see is ciphertext.
- **Secure Boot**: Ensures the ESP32 will only run firmware that has been signed with a trusted cryptographic key. This prevents an attacker from flashing modified firmware.

> These features are supported by the ESP32 hardware and must be configured via `espsecure.py` and `esptool.py` if you want to enable them for a production deployment. They are not enabled by default in the firmware in this repository.

---

## 3. System Architecture

```
┌────────────────────────────────────────────────────────┐
│                    SEALED ENCLOSURE                    │
│                                                        │
│  ┌──────────────┐   UART (9600 baud)  ┌─────────────┐  │
│  │  Arduino Uno │ ◄──────────────────►│    ESP32    │  │
│  │              │  TX→voltage divider │             │  │
│  │  SRAM PUF    │  (5V→3.3V shift)    │  Verifier   │  │
│  │  (the key)   │                     │  NVS flash  │  │
│  └──────────────┘                     │  WiFi host  │  │
│                                       │             │  │
│  ┌─────────┐  ┌─────────┐  ┌───────┐  │  Tamper     │  │
│  │   LDR   │  │ SW-420  │  │LM393  │──►  monitor    │  │
│  │ (light) │  │(vibrat.)│  │(volt.)│  │             │  │
│  └────┬────┘  └────┬────┘  └───┬───┘  └──────┬──────┘  │
│       └────────────┴───────────┘             │         │
│                                              │         │
└──────────────────────────────────────────────┼─────────┘
                                               │
                    ┌──────────────────────────┼────────┐
                    │         OUTSIDE          │        │
                    │                          ▼        │
                    │   [Auth Button]   [OLED Display]  │
                    │   [RGB LED]       [Relay → Lock]  │
                    └────────────────────────────────── ┘
```

**Key design rule:** Everything sensitive lives *inside* the sealed box. The user interacts only with the exterior: a button, an LED, and a display. The solenoid lock output, power cable, and wireless antenna are the only things that pass through the enclosure wall.

> **Critical:** If the Arduino is ever placed *outside* the enclosure, an attacker can unplug it, boot it with their own firmware, read the SRAM at startup, and clone the PUF. The light-based tamper detection only protects you if *opening the box* is what exposes the Arduino.

---

## 4. The Key Lifecycle

### Phase 1 — Enrollment (Done Once)

Enrollment builds the reference fingerprint. The ESP32 collects **5 PUF readings across 5 separate Arduino power cycles** and uses a per-bit majority vote to build a *stable* reference — eliminating any bits that flip inconsistently between boots.

```
1. Assemble hardware. Power on. ESP32 waits for Arduino.
2. Arduino boots → SRAM settles → sends "GHOSTKEY_READY"
3. ESP32 requests raw PUF reading (Sample 1 of 5)
4. You power-cycle the Arduino when prompted (Samples 2–5)
   — The OLED displays "Power Cycle Arduino / Waiting..."
   — The blue LED flashes while waiting
5. After 5 samples:
   • Majority vote → stabilised reference PUF
   • Stability mask computed (marks which bits were rock-solid)
   • Both stored in ESP32 NVS flash
6. Seal the enclosure. Enrollment is locked. System is armed.
```

The stability mask is important: during authentication, only the bits marked as stable in all 5 samples are counted. Noisy bits are silently excluded from comparison, preventing false rejections of the legitimate Arduino due to temperature drift.

---

### Phase 2 — Authentication (Every Access Attempt)

```
1. User presses the auth button on the outside of the box.
2. ESP32 generates 64 fresh random bytes from its hardware RNG.
3. ESP32 derives what the response SHOULD be (using stored PUF + challenge).
4. ESP32 sends the challenge to the Arduino over UART.
5. Arduino mixes the challenge with its live SRAM fingerprint → sends response.
6. ESP32 computes masked Hamming distance between expected and received.
7. Distance ≤ 10% of stable bit count → AUTHENTICATED
   • Relay activates for 3 seconds
   • OLED: "ACCESS GRANTED" / LED: Green
8. Distance > threshold → REJECTED
   • OLED: "ACCESS DENIED" / LED: Red (2 seconds)
```

The user never touches the Arduino. All interaction is through the exterior of the box.

---

### Phase 3 — Tamper Event

```
1. Any tamper sensor fires (light / vibration / voltage)
2. ESP32 immediately wipes NVS flash ("ghostkey" namespace cleared)
3. OLED: "!!! TAMPER !!!" / LED: Solid Red
4. All future authentication attempts fail permanently
5. The device must be physically re-enrolled by an administrator to recover
```

**What the attacker gains:** Nothing. Triggering tamper detection only locks everyone out. The attacker cannot recover the enrolled PUF data — it has been overwritten.

---

### De-enrollment & Re-enrollment

**De-enrollment** deletes the challenge-response profile from the ESP32's flash. The Arduino itself is unchanged — its SRAM fingerprint is a permanent physical property — but without a matching profile on the ESP32, it cannot authenticate.

De-enrollment methods, in order of security:

1. **PIN-protected command via web dashboard** *(most secure — recommended for production)*
2. **Serial command from a connected computer** *(requires physical access to the USB port)*
3. **Physical button hold (5 seconds)** *(simplest, least secure)*

The complete key lifecycle — Enrollment → Active Use → Revocation → Re-enrollment with a new authorised device — is what distinguishes a real security system from a demo. If an Arduino is lost or stolen, the ESP32-side profile must be revocable.

---

## 5. Hardware & Wiring

### Components List

| # | Component | Qty | Approx. Cost (₹) | Role |
|---|---|---|---|---|
| 1 | ESP32 Development Board | ×1 | 400–500 | Verifier, tamper monitor, WiFi host, relay controller |
| 2 | Arduino Uno | ×1 | 300–400 | PUF token — SRAM fingerprint is the key |
| 3 | LDR (Light Dependent Resistor) | ×1 | 20–30 | Detects enclosure being opened |
| 4 | SW-420 Vibration Sensor Module | ×1 | 60–80 | Detects physical probing or tampering |
| 5 | LM393 Comparator Module | ×1 | 30–50 | Monitors power rail for voltage glitch attacks |
| 6 | 5V Single Channel Relay Module | ×1 | 60–80 | Controls the lock output |
| 7 | Solenoid Lock or LED Array | ×1 | 150–300 | Protected output / visual demo |
| 8 | 0.96" I2C OLED Display (SH1106 or SSD1306) | ×1 | 150–200 | Live authentication status |
| 9 | 10kΩ Resistors | ×10 | 20 | LDR voltage divider, logic level shifting |
| 10 | 20kΩ Resistors | ×2 | 10 | Logic level shifting (Arduino 5V → ESP32 3.3V) |
| 11 | 220Ω Resistors | ×10 | 15 | Current limiting for RGB LED |
| 12 | RGB LED (Common Cathode) | ×1 | 20 | Green = auth, Red = tamper, Blue = standby |
| 13 | 100nF Ceramic Capacitors | ×2 | 20 | Power rail decoupling |
| 14 | Full-Size Breadboard | ×1 | 80–100 | Prototyping |
| 15 | Jumper Wires (M-M and M-F) | ×1 pack | 100–150 | Connections |
| 16 | Small Plastic Project Box (~15×10×5 cm) | ×1 | 100–150 | Enclosure — essential for tamper demo |
| 17 | USB Power Supply / 5V Adapter | ×1 | Owned | Power |

**Total: ₹1,540 – ₹2,130** (Budget: ₹3,000)

> The enclosure must be **dark inside** under normal operation for the LDR tamper detection to work. A well-sealed cardboard box is perfectly acceptable for a demo or course project — it doesn't need to be fortress-grade.

---

### Wiring Diagram

**Arduino Uno → ESP32 connections:**

| Arduino Pin | Connection | ESP32 Pin | Note |
|---|---|---|---|
| TX (Pin 1) | → 10kΩ+20kΩ voltage divider → | GPIO16 (RX2) | 5V stepped down to 3.3V |
| RX (Pin 0) | → direct → | GPIO17 (TX2) | No shifting needed (3.3V reads as HIGH on Arduino) |
| GND | → direct → | GND | Common ground required |
| 5V | → direct → | VIN | Powers the ESP32 |

**ESP32 GPIO assignments:**

| GPIO | Connected To | Notes |
|---|---|---|
| GPIO16 | Arduino TX (via voltage divider) | UART RX |
| GPIO17 | Arduino RX | UART TX |
| GPIO34 | LDR output | ADC input (analog) |
| GPIO35 | SW-420 vibration sensor DO | Digital, active-low |
| GPIO36 | LM393 comparator output | Digital, active-low on trigger |
| GPIO26 | Relay IN | Digital output |
| GPIO21 | OLED SDA | I2C data |
| GPIO22 | OLED SCL | I2C clock |
| GPIO25 | RGB LED — Red | Via 220Ω resistor |
| GPIO33 | RGB LED — Green | Via 220Ω resistor |
| GPIO32 | RGB LED — Blue | Via 220Ω resistor |
| GPIO4 | Auth button | INPUT_PULLUP (active-low) |

---

### Logic Level Shifting

The Arduino Uno runs on **5V logic**. The ESP32 runs on **3.3V logic**. Directly connecting Arduino TX to ESP32 RX *will damage the ESP32's GPIO pins over time*.

The solution is a resistor voltage divider on the Arduino TX → ESP32 RX line:

```
Arduino TX (5V) ──┬── 10kΩ ──┬── ESP32 GPIO16 (3.3V)
                  │          │
                 GND        20kΩ
                             │
                            GND
```

The output voltage is: `5V × (20kΩ / (10kΩ + 20kΩ)) = 3.33V` — safely within ESP32 tolerance.

The return path (ESP32 TX → Arduino RX) requires no level shifting, because the Arduino Uno's RX pin will read 3.3V as a valid HIGH.

---

## 6. Software Overview

### Arduino Firmware (`arduino_uno.ino`)

The Arduino's job is simple: capture its SRAM fingerprint on boot and respond to challenges.

**Key mechanism — `.noinit` section:**

```cpp
volatile uint8_t puf_raw[PUF_SIZE] __attribute__((section(".noinit")));
```

The `__attribute__((section(".noinit")))` directive tells the C runtime **not to zero this array before `setup()` runs**. The raw SRAM power-on state — random 1s and 0s determined by the chip's physical imperfections — is preserved here and copied into `puf_fingerprint[]` at startup.

**Serial protocol (commands from ESP32):**

| Command | Arduino Response | Purpose |
|---|---|---|
| `CHALLENGE:<hex>` | `RESPONSE:<hex>` | Authentication round |
| `GET_PUF_HEX` | `PUF_HEX:<hex>` | Enrollment only (exposes raw PUF) |
| `GET_STATS` | Bit distribution stats | Diagnostics |
| `PING` | `PONG` | Heartbeat / connectivity check |

**Heartbeat:** Before the ESP32 makes first contact, the Arduino broadcasts `GHOSTKEY_READY` every 2 seconds. This stops immediately after any command is received, so the periodic announcements cannot corrupt the enrollment sampling window.

**The `derive_response()` function** applies a rolling XOR-hash to the challenge, mixing in the PUF fingerprint byte-by-byte. Each response byte depends on all previous bytes (via `prev`), preventing simple algebraic attacks. The identical algorithm runs on the ESP32 side to predict the expected response independently.

---

### ESP32 Firmware (`esp_32.ino`)

The ESP32 is the brains: it manages enrollment, drives authentication, controls outputs, and monitors all three tamper sensors every loop iteration.

**Enrollment (`enroll()`):**

The enrollment process collects 5 PUF readings across 5 separate Arduino power cycles and uses a **per-bit majority vote** to build a stable reference fingerprint:

```
For each of the 512 bits in the PUF:
  Count how many of the 5 samples had this bit = 1
  If count ≥ 3 → reference bit = 1
  If count < 3 → reference bit = 0

For the stability mask:
  If a bit was ever different between any two samples → mark as unstable (0)
  Unstable bits are excluded from Hamming distance during authentication
```

This two-pass approach (majority vote + direct flip detection) is more robust than either method alone.

**Authentication (`run_challenge_response()`):**

```
1. Load stored PUF + stability mask from NVS
2. Compute stable bit count from mask
3. Effective threshold = stable_bit_count / 10  (10% tolerance)
4. Generate 64 random bytes via ESP32 hardware RNG (esp_random())
5. Derive expected response from stored PUF + challenge
6. Send challenge to Arduino, receive its response
7. masked_hamming_distance(expected, received, mask) ≤ threshold → PASS
```

**Storage (`store_puf()` / `load_puf()`):**

The stabilised PUF and stability mask are stored in the ESP32's NVS (Non-Volatile Storage) under the namespace `"ghostkey"`. NVS survives reboots but is wiped by `wipe_enrollment()` on tamper detection.

**Tamper detection (`check_tamper()`):**

Called at the top of every `loop()` iteration — highest priority. The sensor logic:

```cpp
// LDR: HIGH value = light detected
if (analogRead(PIN_LDR) > 50) → trigger_tamper("LIGHT_DETECTED")

// Voltage comparator: active-low on anomaly
if (digitalRead(PIN_VOLTAGE) == LOW) → trigger_tamper("VOLTAGE_GLITCH")
```

> The vibration sensor code is included but commented out in the current build. See [Calibration & Tuning](#8-calibration--tuning) for why, and how to enable it.

**OLED display:** The project uses the `U8g2` library. The default configuration targets a **SH1106 128×64 controller** (common on 1.3" displays). If your display uses the SSD1306 controller (common on 0.96" displays), change `U8G2_SH1106_128X64_NONAME_F_HW_I2C` to `U8G2_SSD1306_128X64_NONAME_F_HW_I2C` in the firmware.

---

## 7. Getting Started

### Prerequisites

- [Arduino IDE](https://www.arduino.cc/en/software) (1.8.x or 2.x)
- ESP32 board support installed ([installation guide](https://docs.espressif.com/projects/arduino-esp32/en/latest/installing.html))
- Arduino IDE libraries:
  - `U8g2` by olikraus (install via Sketch → Include Library → Manage Libraries)

### Step 1 — Flash the Arduino

1. Open `arduino_uno.ino` in the Arduino IDE.
2. Select **Board: Arduino Uno** and the correct COM port.
3. Upload.

> **Do not open the Serial Monitor yet.** The Arduino begins broadcasting `GHOSTKEY_READY` over its TX pin. Opening the monitor now won't interfere, but it's good habit to leave the UART line quiet until enrollment.

### Step 2 — Flash the ESP32

1. Open `esp_32.ino` in the Arduino IDE.
2. Select your ESP32 board (e.g. **ESP32 Dev Module**) and the correct COM port.
3. Before uploading, **remove the temporary test line** that clears NVS on every boot (it is flagged with `//TEMPORARY TESTING CODE` in `setup()`):

```cpp
// REMOVE THESE THREE LINES BEFORE PRODUCTION USE:
prefs.begin("ghostkey", false);
prefs.clear();
prefs.end();
```

4. Upload.

### Step 3 — Wire Everything

Follow the [Wiring Diagram](#wiring-diagram) above. Double-check:
- The voltage divider on Arduino TX → ESP32 GPIO16.
- Common ground between Arduino and ESP32.
- LDR is inside the enclosure (it needs to be in the dark).

### Step 4 — Enroll

1. Power on the system with the enclosure open.
2. Watch the OLED. It will display **"Waiting for Arduino Uno..."** then **"Starting Enrollment"**.
3. When prompted on the OLED (**"Power Cycle Arduino / Waiting..."**), unplug and replug the Arduino's power.
4. Repeat for all 5 samples. The blue LED flashes between each power cycle to indicate it is waiting.
5. After the 5th sample, the OLED shows **"Enrollment Complete / System Armed"**.
6. **Seal the enclosure.** The system is now live.

You can also monitor enrollment progress over the ESP32's USB serial port at **115200 baud** for detailed logging.

### Step 5 — Test Authentication

Press the auth button on the outside of the enclosure.
- **Green LED + "ACCESS GRANTED"** → relay activates for 3 seconds.
- **Red LED + "ACCESS DENIED"** → response didn't match.

---

## 8. Calibration & Tuning

### LDR Threshold

The LDR tamper threshold is currently:

```cpp
if (analogRead(PIN_LDR) > 50) → trigger_tamper
```

This value will need adjustment depending on your enclosure material and ambient conditions. To calibrate:
1. Seal the enclosure and note the LDR reading (ESP32 serial monitor, add a debug print).
2. Set the threshold to roughly 2–3× that value.
3. Open the enclosure and confirm the reading exceeds the threshold.

### Vibration Sensor

The vibration sensor code is **commented out** in the current build. This is intentional — the SW-420 module is very sensitive and can produce false positives from button presses and normal handling. To enable it, uncomment the vibration block in `check_tamper()` and tune the `low_duration` threshold (currently `> 199 ms`) so that a button press (brief LOW) is not mistaken for an attack (sustained LOW).

### Enrollment Samples

`ENROLLMENT_SAMPLES` is set to 5. Increasing this (e.g. to 7–10) produces a more stable reference fingerprint at the cost of requiring more power cycles during enrollment. For most Arduino Unos, 5 samples is sufficient.

### Match Threshold

The authentication threshold is dynamically computed as **10% of the stable bit count**. For a typical enrollment producing ~400 stable bits, this is a tolerance of ~40 flipped bits out of 400 — roughly 10%. You can tighten this by reducing the divisor in `run_challenge_response()`:

```cpp
uint16_t effective_threshold = stable_bit_count / 10;  // 10% — change this
```

Tightening increases security but also increases the risk of false rejections if temperature varies significantly between enrollment and authentication.

---

## 9. Honest Limitations

GhostKey is designed to be a learning project and demonstration platform. Its design involves real trade-offs that are worth understanding clearly.

**GhostKey authenticates hardware, not people.** Whoever physically possesses the Arduino can authenticate. For a complete access control system, a human factor (PIN keypad, NFC card, biometric) must be added on top. The PUF layer then authenticates the *authenticator* — ensuring the machine checking your PIN hasn't been swapped — while the human factor ensures the right person is present.

**"Nothing is stored to steal" is imprecise.** Nothing is stored *inside the Arduino* (the key). But the ESP32 stores the enrolled challenge-response database in flash, and this is a real attack target. This is still a meaningful advantage over password systems — the secret lives on the verifier side, which you control and protect — but the claim requires qualification.

**Physical access is the hard limit.** If an attacker has enough access to swap the ESP32 and NFC reader, they also have enough access to open the enclosure and steal the Arduino. The tamper detection raises the cost and difficulty of attack, but does not make it impossible. GhostKey is most defensible for **remote and unattended device identity verification** (IoT, supply chain, military hardware) where no human is in the loop. For a local physical door lock, a well-protected NFC system achieves similar security at lower complexity.

**The mixing algorithm is project-grade, not production-grade.** A production PUF system would use `HMAC-SHA256(puf_key, challenge)` for the response derivation. The rolling XOR-hash used here is resistant to passive eavesdropping at practical scales but would not withstand a determined cryptanalytic attack with thousands of collected (challenge, response) pairs.

---

## 10. Real-World Applications

The PUF and challenge-response concepts GhostKey demonstrates are used in:

- **Anti-counterfeiting** — verifying that hardware components (microchips, pharmaceuticals, luxury goods) are genuine, not clones.
- **IoT device identity** — proving that a sensor reporting data to a cloud platform is the actual enrolled device, not an impersonator.
- **Supply chain verification** — detecting component swaps or substitutions during shipping and logistics.
- **Hardware Security Modules (HSMs)** — the tamper-detection-with-data-wipe pattern is used in ATMs, voting machines, and data centre hardware.
- **Military hardware verification** — ensuring field equipment hasn't been replaced or tampered with.
- **Secure Boot / Hardware Root of Trust** — the ESP32 eFuse and Flash Encryption features demonstrated here are the same mechanisms used in enterprise secure boot chains.

---

## 11. Frequently Asked Questions

**Why not just use a fingerprint scanner?**

Fingerprint scanners authenticate *people*. PUFs authenticate *hardware*. They solve different problems. A fingerprint scanner cannot verify that a server, IoT sensor, or hardware component in a supply chain hasn't been physically swapped. For local person-authentication at a door, a fingerprint scanner is simpler and more practical — GhostKey operates at a different layer of the security stack.

**Why use a PUF if you're adding a PIN or NFC on top?**

The PIN or NFC authenticates the *person*. The PUF authenticates the *machine doing the authentication* — ensuring it hasn't been physically replaced with a fake that skims your credentials. This is called a substitution attack, and it is a documented real-world technique against ATMs and access control panels. An ATM does exactly this kind of hardware self-verification before accepting your PIN. Without the PUF layer, an attacker who swaps the reader hardware has a clean credential-stealing attack with no detection.

**Can't an attacker just steal the Arduino?**

Yes — and if they have that level of physical access, they can probably also access the ESP32. The tamper detection significantly raises the cost and complexity of a successful attack (they must defeat three independent sensors without triggering any of them, and do so before the firmware can react), but it does not make the system unbreakable. GhostKey is best understood as a demonstration of real hardware security concepts and as a platform for scenarios where the hardware itself is the thing that needs to be authenticated — not as an impenetrable vault.

**What happens if tamper detection fires by accident?**

The enrolled database is wiped and the device locks until re-enrolled. This is the correct security behaviour — a missed tamper event is a breach, while a false positive is merely a nuisance. The sensitivity of the vibration and LDR thresholds should be tuned carefully during testing in the actual deployment environment.

**My OLED shows nothing / the display is garbled.**

Check whether your OLED uses an **SH1106** or **SSD1306** controller. The firmware defaults to SH1106. Change the constructor in `esp_32.ino` if yours is an SSD1306:

```cpp
// For SSD1306:
U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0, U8X8_PIN_NONE, 22, 21);

// For SH1106 (default):
U8G2_SH1106_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0, U8X8_PIN_NONE, 22, 21);
```

**Enrollment is failing / the Arduino isn't being detected.**

- Confirm common ground between the Arduino and ESP32.
- Check the voltage divider on the Arduino TX line. Measure the voltage at ESP32 GPIO16 — it should read ~3.3V when the Arduino TX is HIGH.
- Open the ESP32 serial monitor at 115200 baud for detailed error messages.
- Make sure you are not accidentally opening the Arduino's serial monitor at the same time — this locks the USB/UART and prevents the firmware from communicating.

**Authentication keeps failing even with the correct Arduino.**

- The SRAM PUF can drift significantly across large temperature changes. Try authenticating at a temperature closer to the enrollment temperature.
- Check the enrollment summary in the serial log — if `Stable bits` is very low (below 200 out of 512), the fingerprint quality is poor. Re-enroll with more samples.
- Confirm both `derive_response()` (Arduino) and `derive_expected_response()` (ESP32) use identical logic and the same seed (`0x5A`). If you modified one, the other must match exactly.

---

## Licence

This project is released for educational use. See `LICENSE` for details.

---

*Built with an Arduino Uno, an ESP32, and a healthy respect for physics.*
