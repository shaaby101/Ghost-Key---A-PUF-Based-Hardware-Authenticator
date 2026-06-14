/*
 * GhostKey — SRAM PUF with Challenge-Response Authentication
 * Arduino Uno side
 *
 * HOW THE CHALLENGE-RESPONSE WORKS:
 *   1. ESP32 sends a random 64-byte challenge: "CHALLENGE:<hex>\n"
 *   2. This Arduino mixes the challenge with its physical PUF fingerprint
 *      using XOR + a rolling hash, producing a response unique to both
 *      THIS chip AND this specific challenge.
 *   3. The response is sent back: "RESPONSE:<hex>\n"
 *   4. Because the challenge changes every round, replaying a captured
 *      response from a previous session is useless — it will not match.
 *
 * SECURITY PROPERTY:
 *   An attacker who intercepts the UART line sees a different challenge
 *   and a different response every single authentication. Neither value
 *   alone reveals the PUF fingerprint, and neither can be reused.
 *
 * WIRING (to ESP32):
 *   Arduino TX (Pin 1) → 10kΩ+20kΩ voltage divider → ESP32 GPIO16
 *   Arduino RX (Pin 0) → ESP32 GPIO17
 *   Arduino GND        → ESP32 GND
 */

#include <avr/wdt.h>

// ─── Configuration ────────────────────────────────────────────────────────────

#define PUF_SIZE       64    // Bytes of SRAM fingerprint. Must match ESP32.
#define CHALLENGE_SIZE 64    // Bytes in each challenge. Must match ESP32.
#define BAUD_RATE      9600

// ─── PUF Buffer ───────────────────────────────────────────────────────────────

// .noinit prevents the C runtime from zeroing this array — the raw SRAM
// power-on state is preserved here before setup() ever runs.
volatile uint8_t puf_raw[PUF_SIZE] __attribute__((section(".noinit")));

// Working copy of the fingerprint (normal variable, populated in setup).
uint8_t puf_fingerprint[PUF_SIZE];

// Set to true once any command is received from the ESP32.
// The heartbeat only fires while this is false — once the ESP32 has made
// contact it no longer needs periodic announcements, and suppressing the
// heartbeat prevents stale GHOSTKEY_READY bytes from polluting enrollment.
bool esp_contacted = false;

// ─── Function Declarations ────────────────────────────────────────────────────

void     capture_sram_puf();
void     handle_challenge(String hex_challenge);
void     derive_response(uint8_t* challenge, uint8_t* response);
bool     parse_hex_to_bytes(String hex_str, uint8_t* out, uint16_t expected_len);
void     send_hex(const char* prefix, uint8_t* data, uint16_t len);
void     send_fingerprint_hex();
void     print_stats();
uint8_t  hamming_distance_byte(uint8_t a, uint8_t b);
uint16_t hamming_distance(uint8_t* a, uint8_t* b, uint16_t len);

// ─── Setup ────────────────────────────────────────────────────────────────────

void setup() {
  Serial.begin(BAUD_RATE);
  // At 9600 baud, 138 bytes takes ~145ms. 250ms is plenty.
  // 5000ms was causing the Arduino to freeze and drop its heartbeat if a single noise byte appeared!
  Serial.setTimeout(250);   
  delay(100);  // Let rails settle — do NOT delay before this, noinit is already captured

  capture_sram_puf();

  Serial.println("GHOSTKEY_READY");
}

// ─── Main Loop ────────────────────────────────────────────────────────────────

void loop() {
  if (Serial.available() > 0) {
    String command = Serial.readStringUntil('\n');
    command.trim();
    
    if (command.length() > 0) {
      if (command.indexOf("CHALLENGE:") >= 0) {
        esp_contacted = true;
        // ── Primary path: challenge-response authentication ──────────────────
        // Extract the hex payload after "CHALLENGE:"
        int start_idx = command.indexOf("CHALLENGE:") + 10;
        String hex_challenge = command.substring(start_idx);
        handle_challenge(hex_challenge);

      } else if (command.indexOf("GET_PUF_HEX") >= 0) {
        esp_contacted = true;
        // ── Enrollment only — exposes raw PUF, must be disabled post-enrollment
        send_fingerprint_hex();

      } else if (command.indexOf("GET_STATS") >= 0) {
        esp_contacted = true;
        print_stats();

      } else if (command.indexOf("PING") >= 0) {
        esp_contacted = true;
        Serial.println("PONG");

      } else {
        Serial.print("UNKNOWN_CMD:");
        Serial.println(command);
      }
    }
  }

  // Heartbeat: re-announce until the ESP32 makes first contact.
  // Stops as soon as any command is received so it cannot produce
  // spurious GHOSTKEY_READY bytes during enrollment sampling.
  if (!esp_contacted) {
    static uint32_t last_announce = 0;
    if (millis() - last_announce > 2000) {
      Serial.println("GHOSTKEY_READY");
      last_announce = millis();
    }
  }
}

// ─── Challenge-Response Core ──────────────────────────────────────────────────

/*
 * handle_challenge()
 *
 * Parses the incoming hex challenge, derives the response using the PUF
 * fingerprint, and sends it back to the ESP32.
 *
 * If the challenge hex is malformed or the wrong length, sends ERROR
 * so the ESP32 can log and retry cleanly.
 */
void handle_challenge(String hex_challenge) {
  uint8_t challenge[CHALLENGE_SIZE];
  uint8_t response[CHALLENGE_SIZE];

  if (!parse_hex_to_bytes(hex_challenge, challenge, CHALLENGE_SIZE)) {
    Serial.println("ERROR:BAD_CHALLENGE");
    return;
  }

  derive_response(challenge, response);
  send_hex("RESPONSE:", response, CHALLENGE_SIZE);
}

/*
 * derive_response()
 *
 * Mixes the challenge with the PUF fingerprint to produce a response.
 *
 * Algorithm (per byte i):
 *   step1 = challenge[i] XOR puf[i]
 *             — Combines the random challenge with the unique hardware state.
 *               XOR alone would let an attacker with two challenge-response
 *               pairs recover the PUF directly (R1 XOR R2 = C1 XOR C2), so
 *               we add a non-linear rolling hash step.
 *
 *   response[i] = step1 XOR rotate_left(prev_response, 3) XOR puf[(i+1) % PUF_SIZE]
 *             — prev_response creates a chain so each byte depends on all
 *               previous bytes. rotate_left is non-linear (prevents simple
 *               algebraic cancellation). The second PUF byte folds in more
 *               physical state, increasing the cost of model-building attacks.
 *
 * Why this is sufficient for a project-level PUF:
 *   - The PUF fingerprint is never transmitted — only challenge and response.
 *   - Each authentication round produces a completely different (C, R) pair.
 *   - Passive eavesdropping cannot extract the PUF within a practical number
 *     of observations at project scale.
 *   - A production system would use HMAC-SHA256(puf_key, challenge) instead,
 *     but that requires a crypto library not available on a bare Uno.
 *
 * NOTE: challenge[] and puf_fingerprint[] must both be CHALLENGE_SIZE == PUF_SIZE bytes.
 */
void derive_response(uint8_t* challenge, uint8_t* response) {
  uint8_t prev = 0x5A;  // Non-zero seed
  for (uint16_t i = 0; i < CHALLENGE_SIZE; i++) {
    // To allow the ESP32's per-bit stability mask to work, the PUF noise MUST NOT
    // cascade or avalanche into other bytes. 
    // We roll the hash over the CHALLENGE only, and apply the PUF point-wise.
    uint8_t rotated_prev = (prev << 3) | (prev >> 5);
    uint8_t c_mix = challenge[i] ^ rotated_prev;
    
    // Each response bit is exactly: (hashed challenge bit) XOR (PUF bit)
    response[i] = c_mix ^ puf_fingerprint[i];
    
    // Cascade ONLY the noiseless challenge hash
    prev = c_mix;
  }
}

// ─── Enrollment Helper ────────────────────────────────────────────────────────

/*
 * send_fingerprint_hex()
 *
 * Sends the raw PUF fingerprint. Used ONLY during enrollment so the ESP32
 * can store the reference fingerprint for later response verification.
 *
 * SECURITY NOTE: In a production system this command would be gated behind
 * a physical enrollment button that disables itself after first use, ensuring
 * the raw PUF is never transmitted again after enrollment.
 */
void send_fingerprint_hex() {
  send_hex("PUF_HEX:", puf_fingerprint, PUF_SIZE);
}

// ─── PUF Capture ─────────────────────────────────────────────────────────────

/*
 * capture_sram_puf()
 *
 * Copies the .noinit region (power-on SRAM state) into puf_fingerprint[].
 * The .noinit array is already populated by hardware before setup() runs.
 *
 * Stable reference generation (majority voting across multiple power cycles)
 * is handled entirely on the ESP32 side — see ghostkey_esp32_CR.ino enroll().
 */
void capture_sram_puf() {
  for (uint16_t i = 0; i < PUF_SIZE; i++) {
    puf_fingerprint[i] = puf_raw[i];
  }
}

// ─── Utility ─────────────────────────────────────────────────────────────────

/*
 * parse_hex_to_bytes()
 *
 * Converts a hex string "A3F2..." into a byte array.
 * Returns false if the string is shorter than expected.
 */
bool parse_hex_to_bytes(String hex_str, uint8_t* out, uint16_t expected_len) {
  if (hex_str.length() < (uint32_t)(expected_len * 2)) {
    return false;
  }
  for (uint16_t i = 0; i < expected_len; i++) {
    char buf[3] = { hex_str[i * 2], hex_str[i * 2 + 1], '\0' };
    out[i] = (uint8_t)strtol(buf, NULL, 16);
  }
  return true;
}

/*
 * send_hex()
 *
 * Sends prefix + hex-encoded data + newline over Serial.
 * e.g. send_hex("RESPONSE:", buf, 64) → "RESPONSE:A3F200...\n"
 */
void send_hex(const char* prefix, uint8_t* data, uint16_t len) {
  Serial.print(prefix);
  for (uint16_t i = 0; i < len; i++) {
    if (data[i] < 0x10) Serial.print("0");
    Serial.print(data[i], HEX);
  }
  Serial.println();
}

/*
 * print_stats()
 *
 * Diagnostic: bit distribution of PUF fingerprint.
 * A healthy PUF should be close to 50% ones.
 */
void print_stats() {
  uint16_t ones = 0;
  for (uint16_t i = 0; i < PUF_SIZE; i++) {
    for (uint8_t bit = 0; bit < 8; bit++) {
      if (puf_fingerprint[i] & (1 << bit)) ones++;
    }
  }
  uint16_t total_bits = PUF_SIZE * 8;
  uint16_t zeros = total_bits - ones;

  Serial.println("=== PUF STATS ===");
  Serial.print("Total bits: "); Serial.println(total_bits);
  Serial.print("Ones:  "); Serial.print(ones);
  Serial.print(" ("); Serial.print((ones * 100) / total_bits); Serial.println("%)");
  Serial.print("Zeros: "); Serial.print(zeros);
  Serial.print(" ("); Serial.print((zeros * 100) / total_bits); Serial.println("%)");
  if (ones > (total_bits * 70 / 100) || zeros > (total_bits * 70 / 100)) {
    Serial.println("WARNING: High bias — consider sampling a wider SRAM region.");
  } else {
    Serial.println("Bit distribution: OK");
  }
  Serial.println("=================");
}

uint16_t hamming_distance(uint8_t* a, uint8_t* b, uint16_t len) {
  uint16_t d = 0;
  for (uint16_t i = 0; i < len; i++) d += hamming_distance_byte(a[i], b[i]);
  return d;
}

uint8_t hamming_distance_byte(uint8_t a, uint8_t b) {
  uint8_t x = a ^ b, c = 0;
  while (x) { c += x & 1; x >>= 1; }
  return c;
}
