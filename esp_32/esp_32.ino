/*
 * GhostKey — Challenge-Response PUF Verifier
 * ESP32 side
 *
 * HOW THE CHALLENGE-RESPONSE WORKS:
 *   Enrollment (once, across ENROLLMENT_SAMPLES power cycles):
 *     1. ESP32 requests ENROLLMENT_SAMPLES PUF readings from the Arduino,
 *        prompting the user to power-cycle the Arduino between each reading.
 *     2. Per-bit majority vote across all samples produces a stabilized
 *        reference PUF, eliminating bits that flip randomly between boots.
 *     3. A stability mask records which bits were identical across ALL samples.
 *        Only stable bits are used during authentication comparison.
 *     4. Both the stabilized PUF and the mask are stored in NVS flash.
 *
 *   Authentication (every access attempt):
 *     1. ESP32 generates a fresh 64-byte random challenge using its hardware RNG.
 *        It is NEVER reused — a new challenge is generated for every single round.
 *     2. ESP32 sends "CHALLENGE:<hex>\n" to the Arduino over UART.
 *     3. Arduino derives a response by mixing the challenge with its PUF fingerprint
 *        using the same derive_response() algorithm stored here on the ESP32.
 *     4. ESP32 independently derives what the response SHOULD be, using the stored
 *        reference fingerprint and the same algorithm.
 *     5. Masked Hamming distance between received vs expected response is calculated,
 *        considering only bits whose PUF source was stable across all enrollment
 *        samples. Threshold = 10% of stable bit count.
 *        Within threshold → AUTHENTICATED. Above threshold → REJECTED.
 *
 * WHY THIS IS REPLAY-PROOF:
 *   An attacker capturing a (challenge, response) pair on the UART line cannot
 *   reuse the response — the next authentication uses a completely different
 *   challenge, so the old response produces the wrong result.
 *
 * WIRING:
 *   ESP32 GPIO16 (RX2) ← 10kΩ+20kΩ voltage divider ← Arduino TX (Pin 1)
 *   ESP32 GPIO17 (TX2) → Arduino RX (Pin 0)
 *   ESP32 GND          → Arduino GND
 *
 * GPIO Assignments (from doc):
 *   GPIO34  LDR (light tamper)
 *   GPIO35  SW-420 vibration sensor
 *   GPIO36  LM393 comparator (voltage glitch)
 *   GPIO26  Relay
 *   GPIO25  RGB LED Red
 *   GPIO33  RGB LED Green
 *   GPIO32  RGB LED Blue
 *   GPIO21  OLED SDA
 *   GPIO22  OLED SCL
 */

#include <Arduino.h>
#include <Preferences.h>   // ESP32 NVS (non-volatile storage, survives reboots)
#include <U8g2lib.h>       // OLED display library
#include <Wire.h>

// ─── Configuration ────────────────────────────────────────────────────────────

#define PUF_SIZE           64      // Must match Arduino's PUF_SIZE
#define CHALLENGE_SIZE     64      // Must match Arduino's CHALLENGE_SIZE
#define BAUD_RATE          9600

#define SERIAL2_RX         16
#define SERIAL2_TX         17

// Number of PUF readings collected across separate power cycles during
// enrollment. Higher values yield a more stable reference at the cost of
// requiring more power cycles from the user.
#define ENROLLMENT_SAMPLES 5

// MATCH_THRESHOLD is no longer used directly — the effective threshold during
// authentication is computed dynamically as 10% of the stable bit count found
// during enrollment. It is kept here only for reference / documentation.
#define MATCH_THRESHOLD    51      // ~10% of 512 bits (reference only)

// GPIO pin assignments
#define PIN_LDR         34
#define PIN_VIBRATION   35
#define PIN_VOLTAGE     36
#define PIN_RELAY       26
#define PIN_LED_RED     25
#define PIN_LED_GREEN   33
#define PIN_LED_BLUE    32

// Auth button (outside the enclosure — triggers an auth round)
#define PIN_AUTH_BTN    4

uint32_t tamper_armed_at = 0;
#define TAMPER_ARM_DELAY_MS 10000

// Relay active duration in ms
#define RELAY_OPEN_MS   3000

uint32_t last_button_press = 0;
#define VIBRATION_COOLDOWN_MS 5000

// ─── State ────────────────────────────────────────────────────────────────────

Preferences prefs;
bool tamper_triggered = false;

// 1.3" OLEDs typically use the SH1106 controller (128x64). 
// If your display uses SSD1306, you can change 'SH1106' to 'SSD1306' in the class name below.
U8G2_SH1106_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0, /* reset=*/ U8X8_PIN_NONE, /* clock=*/ 22, /* data=*/ 21);

// Helper function to update OLED
void update_display(const char* line1, const char* line2 = "", const char* line3 = "", const char* line4 = "") {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_ncenB08_tr); 
  if (line1[0] != '\0') u8g2.drawStr(0, 12, line1);
  if (line2[0] != '\0') u8g2.drawStr(0, 28, line2);
  if (line3[0] != '\0') u8g2.drawStr(0, 44, line3);
  if (line4[0] != '\0') u8g2.drawStr(0, 60, line4);
  u8g2.sendBuffer();
}

// ─── Function Declarations ────────────────────────────────────────────────────

// Enrollment
bool     enroll();
bool     request_raw_puf(uint8_t* puf_out);
void     compute_majority_puf(uint16_t* vote_counts, uint8_t* puf_out);
void     compute_stability_mask(uint16_t* vote_counts, uint8_t* mask_out, uint16_t* stable_count_out);

// Authentication
bool     authenticate();
bool     run_challenge_response(uint8_t* received_response);
void     generate_challenge(uint8_t* challenge);
void     derive_expected_response(uint8_t* stored_puf, uint8_t* challenge, uint8_t* expected);

// Storage
void     store_puf(uint8_t* puf, uint8_t* mask);
bool     load_puf(uint8_t* puf_out, uint8_t* mask_out);
void     wipe_enrollment();
bool     is_enrolled();

// Tamper
void     check_tamper();
void     trigger_tamper(const char* reason);

// Comms helpers
bool     wait_for_ready(uint32_t timeout_ms);
bool     send_challenge_get_response(uint8_t* challenge, uint8_t* response_out);
bool     parse_hex_to_bytes(String hex_str, uint8_t* out, uint16_t expected_len);
void     send_hex_command(const char* prefix, uint8_t* data, uint16_t len);

// Output helpers
void     set_led(bool r, bool g, bool b);
void     open_relay();
void     print_puf(uint8_t* fp);

// Hamming
uint16_t hamming_distance(uint8_t* a, uint8_t* b, uint16_t len);
uint8_t  hamming_distance_byte(uint8_t a, uint8_t b);
uint16_t masked_hamming_distance(uint8_t* a, uint8_t* b, uint8_t* mask, uint16_t len);

// ─── Setup ────────────────────────────────────────────────────────────────────

void setup() {
  Serial2.begin(BAUD_RATE, SERIAL_8N1, SERIAL2_RX, SERIAL2_TX);
  Serial.begin(115200);
  
  // I2C bus clear before display init — prevents hang if bus was left stuck
  Wire.begin(21, 22);
  pinMode(22, OUTPUT);
  for (int i = 0; i < 9; i++) {
    digitalWrite(22, HIGH); delayMicroseconds(10);
    digitalWrite(22, LOW);  delayMicroseconds(10);
  }
  Wire.end();

  u8g2.begin();
  update_display("Booting GhostKey...");

  //TEMPORARY TESTING CODE
  prefs.begin("ghostkey", false);
  prefs.clear();
  prefs.end();

  delay(500);
  Serial.println("\n=== GhostKey ESP32 (Challenge-Response Mode) ===");


  // GPIO setup
  pinMode(PIN_LDR,       INPUT);
  pinMode(PIN_VIBRATION, INPUT);
  pinMode(PIN_VOLTAGE,   INPUT);
  pinMode(PIN_RELAY,     OUTPUT);
  pinMode(PIN_AUTH_BTN,  INPUT_PULLUP);
  pinMode(PIN_LED_RED,   OUTPUT);
  pinMode(PIN_LED_GREEN, OUTPUT);
  pinMode(PIN_LED_BLUE,  OUTPUT);

  digitalWrite(PIN_RELAY, LOW);
  set_led(false, false, true);   // Blue = standby

  Serial.println("Waiting for Arduino...");
  update_display("Waiting for", "Arduino Uno...");
  
  // Flush anything that arrived during display/NVS init
  while (Serial2.available()) Serial2.read();
  delay(50);
  while (Serial2.available()) Serial2.read();

  while (!wait_for_ready(5000)) {
    Serial.println("Arduino not detected. Retrying in 5 seconds...");
    update_display("Arduino not found.", "Retrying in 5s...");
    
    set_led(true, false, false);   // Red = not connected
    delay(5000);
    set_led(false, false, true);   // Blue = trying again
    Serial.println("Retrying...");
    update_display("Waiting for", "Arduino Uno...");
  }
  Serial.println("Arduino detected!");
  update_display("Arduino Detected!", "Verifying enrollment");
  
  // Acknowledge the Arduino to silence its recurring GHOSTKEY_READY heartbeat
  Serial2.println("PING");

  if (!is_enrolled()) {
    Serial.println("No enrollment found — starting majority-vote enrollment...");
    update_display("No Enrollment found", "Starting Enrollment");
    delay(1500);

    if (!enroll()) {
      Serial.println("FATAL: Enrollment failed.");
      update_display("Enrollment ERROR!", "System halted.");
      set_led(true, false, false);
      while (true) delay(1000);
    }
    Serial.println("Enrollment complete. System armed.");
    tamper_armed_at = millis() + TAMPER_ARM_DELAY_MS;
    update_display("Enrollment Complete", "System Armed", "Ready to Auth.");
  } else {
    Serial.println("Enrollment found. Ready for authentication.");
    update_display("Enrollment Found", "System Armed", "Ready to Auth.");
  }

  set_led(false, false, true);  // Blue = standby, waiting for button press
}

// ─── Main Loop ────────────────────────────────────────────────────────────────

void loop() {
  // Tamper sensors are checked every loop — highest priority
  check_tamper();

  if (tamper_triggered) {
    // System locked — nothing else runs until re-enrolled
    set_led(true, false, false);
    delay(500);
    return;
  }
  
  

  // Auth button is active-low (INPUT_PULLUP)
  if (digitalRead(PIN_AUTH_BTN) == LOW) {
    Serial.println("PIN DETECTED LOW");
    delay(50);   // Debounce
    if (digitalRead(PIN_AUTH_BTN) == LOW) {
      Serial.println("\n-- Auth button pressed --");
      last_button_press = millis();
      update_display("Authenticating...", "Checking GhostKey...");
      set_led(false, false, false);  // LEDs off during challenge

      bool result = authenticate();

      if (result) {
        Serial.println(">> ACCESS GRANTED");
        update_display("> ACCESS GRANTED", "Relay Open");
        set_led(false, true, false);   // Green
        open_relay();
        set_led(false, false, true);   // Back to blue standby
        update_display("System Armed", "Ready to Auth.");
      } else {
        Serial.println(">> ACCESS DENIED");
        update_display(">> ACCESS DENIED");
        set_led(true, false, false);   // Red
        delay(2000);
        set_led(false, false, true);   // Back to blue standby
        update_display("System Armed", "Ready to Auth.");
      }

      // Wait for button release before continuing
      while (digitalRead(PIN_AUTH_BTN) == LOW) delay(10);
      Serial.println("-- Button released --");
    }
  }


  delay(20);
}

// ─── Enrollment ──────────────────────────────────────────────────────────────

/*
 * enroll()
 *
 * Collects ENROLLMENT_SAMPLES PUF readings across separate Arduino power
 * cycles. Uses per-bit majority voting to produce a stabilized reference PUF,
 * and computes a stability mask that marks only bits that were identical in
 * ALL samples. Both are stored in NVS.
 *
 * Memory strategy: instead of storing all raw sample buffers simultaneously
 * (which would require ENROLLMENT_SAMPLES * PUF_SIZE bytes), we maintain a
 * uint16_t vote_counts[PUF_SIZE * 8] array — one counter per bit. Each sample
 * increments the counter for every bit that was 1. Memory usage is flat
 * regardless of ENROLLMENT_SAMPLES.
 *
 * An additional uint8_t all_same[PUF_SIZE] per-byte tracker records whether
 * each byte has remained identical so far. After the first sample it is
 * initialized with that byte value; subsequent samples XOR against it — any
 * bit that ever differs will be flagged.
 */
bool enroll() {
  // Per-bit vote counter (one entry per bit across PUF_SIZE bytes).
  // vote_counts[byte_index * 8 + bit_index] counts how many samples had that
  // bit set to 1. Using uint16_t supports up to 65535 samples.
  static uint16_t vote_counts[PUF_SIZE * 8];
  memset(vote_counts, 0, sizeof(vote_counts));

  // Tracks per-byte XOR accumulator: after all samples, any byte position
  // where the value was NOT identical across all samples will have non-zero
  // bits set via the flipped_mask[] check below.
  // We track this at bit granularity using a separate bool array.
  // ever_flipped[bit_index] = true if that bit was ever different between any
  // two consecutive samples (i.e., not stable).
  static bool ever_flipped[PUF_SIZE * 8];
  memset(ever_flipped, 0, sizeof(ever_flipped));

  // Reference values from the first sample, used to detect subsequent flips.
  static uint8_t first_sample[PUF_SIZE];

  uint8_t puf_buf[PUF_SIZE];

  Serial.println("=== Majority-Vote Enrollment ===");
  Serial.print("Collecting ");
  Serial.print(ENROLLMENT_SAMPLES);
  Serial.println(" samples across separate power cycles.");

  for (uint8_t sample = 0; sample < ENROLLMENT_SAMPLES; sample++) {
    if (sample == 0) {
      // Reading 1: Arduino is already up (wait_for_ready succeeded in setup()).
      Serial.println("[Sample 1/5] Collecting initial PUF reading...");
    } else {
      // Readings 2..N: ask user to power cycle the Arduino, then wait.
      Serial.print("[Sample ");
      Serial.print(sample + 1);
      Serial.print("/");
      Serial.print(ENROLLMENT_SAMPLES);
      Serial.println("] Power cycle the Arduino now. Waiting...");
      
      char line1[32];
      sprintf(line1, "Sample %d / %d", sample + 1, ENROLLMENT_SAMPLES);
      update_display(line1, "Power Cycle Arduino", "Waiting...");

      // Flush any stale bytes already in the RX buffer (e.g. a periodic
      // GHOSTKEY_READY the Arduino sent before we started listening) so
      // wait_for_ready() only sees a reply triggered by the power cycle.
      while (Serial2.available()) Serial2.read();

      // Flash blue LED while waiting to signal "expecting power cycle".
      bool led_state = false;
      uint32_t flash_start = millis();
      bool got_ready = false;

      while (millis() - flash_start < 30000) {
        led_state = !led_state;
        digitalWrite(PIN_LED_BLUE, led_state ? HIGH : LOW);
        digitalWrite(PIN_LED_RED,  LOW);
        digitalWrite(PIN_LED_GREEN, LOW);

        // Poll in 500 ms windows to keep the LED flashing at ~1 Hz.
        if (wait_for_ready(500)) {
          got_ready = true;
          break;
        }
      }

      set_led(false, false, true);  // Solid blue while collecting

      if (!got_ready) {
        Serial.println("Enrollment ERROR: Timed out waiting for Arduino power cycle.");
        return false;
      }

      Serial.print("[Sample ");
      Serial.print(sample + 1);
      Serial.println("] Arduino rebooted. Collecting PUF reading...");
    }

    if (!request_raw_puf(puf_buf)) {
      Serial.print("Enrollment ERROR: Failed to read PUF on sample ");
      Serial.println(sample + 1);
      return false;
    }

    // Accumulate this sample into vote_counts and ever_flipped.
    for (uint16_t byte_i = 0; byte_i < PUF_SIZE; byte_i++) {
      for (uint8_t bit_i = 0; bit_i < 8; bit_i++) {
        uint16_t idx = (uint16_t)byte_i * 8 + bit_i;
        uint8_t  bit_val = (puf_buf[byte_i] >> bit_i) & 0x01;

        // Accumulate vote
        if (bit_val) vote_counts[idx]++;

        // On first sample: record reference
        if (sample == 0) {
          first_sample[byte_i] = puf_buf[byte_i];
        } else {
          // Mark unstable if this bit disagrees with the first sample
          uint8_t ref_bit = (first_sample[byte_i] >> bit_i) & 0x01;
          if (bit_val != ref_bit) {
            ever_flipped[idx] = true;
          }
        }
      }
    }

    Serial.print("  Sample ");
    Serial.print(sample + 1);
    Serial.println(" recorded.");
    
    if (sample < ENROLLMENT_SAMPLES - 1) {
      Serial.println("Waiting 5 seconds before the next power cycle...");
      delay(5000);
    }
  }

  // ── Compute stabilized PUF via majority vote ─────────────────────────────
  uint8_t stable_puf[PUF_SIZE];
  compute_majority_puf(vote_counts, stable_puf);

  // ── Compute stability mask ────────────────────────────────────────────────
  uint8_t  stable_mask[PUF_SIZE];
  uint16_t stable_count = 0;
  compute_stability_mask(vote_counts, stable_mask, &stable_count);

  // Fill in ever_flipped bits that were detected directly
  // (compute_stability_mask uses vote_counts thresholds; this pass adds any
  //  bit that literally changed value relative to sample 1).
  for (uint16_t byte_i = 0; byte_i < PUF_SIZE; byte_i++) {
    for (uint8_t bit_i = 0; bit_i < 8; bit_i++) {
      if (ever_flipped[(uint16_t)byte_i * 8 + bit_i]) {
        stable_mask[byte_i] &= ~(1 << bit_i);  // Clear = unstable
      }
    }
  }

  // Recount stable bits after merging both instability detectors
  stable_count = 0;
  for (uint16_t byte_i = 0; byte_i < PUF_SIZE; byte_i++) {
    for (uint8_t bit_i = 0; bit_i < 8; bit_i++) {
      if ((stable_mask[byte_i] >> bit_i) & 0x01) stable_count++;
    }
  }

  uint16_t total_bits = PUF_SIZE * 8;
  Serial.println("=== Enrollment Summary ===");
  Serial.print("Total bits:  "); Serial.println(total_bits);
  Serial.print("Stable bits: "); Serial.print(stable_count);
  Serial.print(" (");
  Serial.print((stable_count * 100UL) / total_bits);
  Serial.println("%)");
  Serial.print("Unstable bits: ");
  Serial.println(total_bits - stable_count);
  Serial.print("Effective auth threshold (10% of stable): ");
  Serial.println(stable_count / 10);

  Serial.print("Stabilized PUF: ");
  print_puf(stable_puf);

  store_puf(stable_puf, stable_mask);
  Serial.println("Stabilized PUF and mask stored in NVS.");
  Serial.println("==========================");

  return true;
}

/*
 * compute_majority_puf()
 *
 * For each bit position, if its vote count exceeds half of ENROLLMENT_SAMPLES,
 * the stable reference bit is 1, otherwise 0. Ties (even ENROLLMENT_SAMPLES,
 * exactly half votes) round to 0 for determinism.
 */
void compute_majority_puf(uint16_t* vote_counts, uint8_t* puf_out) {
  memset(puf_out, 0, PUF_SIZE);
  for (uint16_t byte_i = 0; byte_i < PUF_SIZE; byte_i++) {
    for (uint8_t bit_i = 0; bit_i < 8; bit_i++) {
      uint16_t votes = vote_counts[(uint16_t)byte_i * 8 + bit_i];
      if (votes > ENROLLMENT_SAMPLES / 2) {
        puf_out[byte_i] |= (1 << bit_i);
      }
    }
  }
}

/*
 * compute_stability_mask()
 *
 * A bit is considered stable (mask bit = 1) if it voted the same way in
 * ALL samples: vote count == 0 (always 0) or vote count == ENROLLMENT_SAMPLES
 * (always 1). Any intermediate count means the bit flipped at least once.
 *
 * Also outputs *stable_count_out with the number of stable bits found.
 * NOTE: enroll() subsequently merges the ever_flipped[] tracker, so the
 * count returned here may be refined before final storage.
 */
void compute_stability_mask(uint16_t* vote_counts, uint8_t* mask_out, uint16_t* stable_count_out) {
  memset(mask_out, 0, PUF_SIZE);
  *stable_count_out = 0;
  for (uint16_t byte_i = 0; byte_i < PUF_SIZE; byte_i++) {
    for (uint8_t bit_i = 0; bit_i < 8; bit_i++) {
      uint16_t votes = vote_counts[(uint16_t)byte_i * 8 + bit_i];
      if (votes == 0 || votes == ENROLLMENT_SAMPLES) {
        mask_out[byte_i] |= (1 << bit_i);  // Stable
        (*stable_count_out)++;
      }
      // Else: intermediate vote count → unstable → mask bit stays 0
    }
  }
}

/*
 * request_raw_puf()
 *
 * Sends GET_PUF_HEX and waits for "PUF_HEX:<hex>" response.
 * Used only during enrollment. The Arduino's GET_PUF_HEX handler should be
 * disabled or gated after enrollment in a production system.
 */
bool request_raw_puf(uint8_t* puf_out) {
  // Flush before asking
  while (Serial2.available()) Serial2.read();
  
  Serial2.println("GET_PUF_HEX");

  uint32_t start = millis();
  String line = "";

  while (millis() - start < 5000) {
    while (Serial2.available()) {
      char c = (char)Serial2.read();
      if (c == '\n') {
        line.trim();
        if (line.startsWith("PUF_HEX:")) {
          String hex_data = line.substring(8);
          if (parse_hex_to_bytes(hex_data, puf_out, PUF_SIZE)) {
            return true;
          } else {
            Serial.print("CR ERROR: Truncated PUF_HEX received! Length: ");
            Serial.println(hex_data.length());
            // Instead of returning false immediately, we wait to see if it retries or we just send the command again.
            Serial2.println("GET_PUF_HEX"); 
          }
        }
        line = "";
      } else if (c >= 32 && c <= 126) {
        line += c;
      }
    }
    
    // Periodically re-send the request just in case the Arduino missed it due to noise
    if (millis() - start > 0 && (millis() - start) % 1000 == 0) {
      Serial2.println("GET_PUF_HEX");
    }
    
    delay(10);
  }
  return false;
}

// ─── Authentication ───────────────────────────────────────────────────────────

/*
 * authenticate()
 *
 * Runs one full challenge-response round.
 * Returns true if the Arduino's response matches within masked Hamming threshold.
 */
bool authenticate() {
  if (!is_enrolled()) {
    Serial.println("AUTH ERROR: Not enrolled.");
    return false;
  }

  // if Arduino just rebooted, let it finish announcing itself
  // Flush stale bytes, then give a short window for any in-flight GHOSTKEY_READY
  while (Serial2.available()) Serial2.read();
  delay(100);  // Let any partially-arrived line finish transmitting
  while (Serial2.available()) Serial2.read();  // Flush again

  uint8_t received_response[CHALLENGE_SIZE];

  if (!run_challenge_response(received_response)) {
    Serial.println("AUTH ERROR: Challenge-response exchange failed.");
    return false;
  }

  return true;  // Result already evaluated inside run_challenge_response()
}

/*
 * run_challenge_response()
 *
 * The full protocol in one function:
 *   1. Load the stored reference PUF and stability mask.
 *   2. Generate a fresh random challenge.
 *   3. Derive the expected response locally (from stored PUF + challenge).
 *   4. Send the challenge to the Arduino, wait for its response.
 *   5. Compare received vs expected using masked Hamming distance
 *      (only bits whose PUF source was stable across all enrollment samples).
 *   6. Threshold = 10% of stable bit count.
 *   7. Return the comparison result.
 *
 * received_response_out is populated with what the Arduino actually sent,
 * for logging purposes.
 */
bool run_challenge_response(uint8_t* received_response_out) {
  uint8_t stored_puf[PUF_SIZE];
  uint8_t stable_mask[PUF_SIZE];

  if (!load_puf(stored_puf, stable_mask)) {
    Serial.println("CR ERROR: Could not load stored PUF.");
    return false;
  }

  // Compute stable bit count from mask (used for threshold and logging)
  uint16_t stable_bit_count = 0;
  for (uint16_t byte_i = 0; byte_i < PUF_SIZE; byte_i++) {
    for (uint8_t bit_i = 0; bit_i < 8; bit_i++) {
      if ((stable_mask[byte_i] >> bit_i) & 0x01) stable_bit_count++;
    }
  }

  // Effective threshold: 10% of stable bits.
  // Falls back to MATCH_THRESHOLD if no mask was stored (all bits stable).
  uint16_t effective_threshold = (stable_bit_count > 0)
    ? (stable_bit_count / 10)
    : MATCH_THRESHOLD;

  // Step 1: Generate a fresh random challenge
  uint8_t challenge[CHALLENGE_SIZE];
  generate_challenge(challenge);

  Serial.print("Challenge: ");
  print_puf(challenge);

  // Step 2: Derive what we EXPECT the Arduino to respond
  uint8_t expected_response[CHALLENGE_SIZE];
  derive_expected_response(stored_puf, challenge, expected_response);

  // Step 3: Send challenge to Arduino, receive its response
  if (!send_challenge_get_response(challenge, received_response_out)) {
    Serial.println("CR ERROR: No response from Arduino.");
    return false;
  }

  Serial.print("Expected:  ");
  print_puf(expected_response);
  Serial.print("Received:  ");
  print_puf(received_response_out);

  // Step 4: Compare with masked Hamming distance
  // Only bits whose PUF source was stable across all enrollment samples are
  // included. Noisy/unstable bits are ignored in both the distance and the
  // denominator so they cannot cause spurious rejections.
  uint16_t distance = masked_hamming_distance(
    expected_response, received_response_out, stable_mask, CHALLENGE_SIZE
  );

  Serial.println("=== Authentication Result ===");
  Serial.print("Stable bits used:    "); Serial.println(stable_bit_count);
  Serial.print("Masked Hamming dist: ");
  Serial.print(distance);
  Serial.print(" / ");
  Serial.println(stable_bit_count);
  Serial.print("Difference:          ");
  if (stable_bit_count > 0) {
    Serial.print((distance * 100UL) / stable_bit_count);
  } else {
    Serial.print("N/A");
  }
  Serial.println("%");
  Serial.print("Effective threshold: ");
  Serial.print(effective_threshold);
  Serial.print(" bits (10% of ");
  Serial.print(stable_bit_count);
  Serial.println(" stable bits)");

  bool match = (distance <= effective_threshold);
  Serial.println(match ? "Result: AUTHENTICATED" : "Result: REJECTED");
  Serial.println("=============================");

  return match;
}

/*
 * generate_challenge()
 *
 * Fills the buffer with random bytes from ESP32's hardware RNG (esp_random()).
 * This is a true hardware random number generator seeded from thermal noise —
 * not a pseudo-RNG. Challenges are never stored or reused.
 */
void generate_challenge(uint8_t* challenge) {
  for (uint16_t i = 0; i < CHALLENGE_SIZE; i++) {
    challenge[i] = (uint8_t)(esp_random() & 0xFF);
  }
}

/*
 * derive_expected_response()
 *
 * Mirrors the Arduino's derive_response() exactly.
 * Both sides must use identical logic — if these diverge, auth always fails.
 *
 * Algorithm (per byte i):
 *   step1      = challenge[i] XOR stored_puf[i]
 *   rotated    = rotate_left(prev, 3)
 *   response[i] = step1 XOR rotated XOR stored_puf[(i+1) % PUF_SIZE]
 *   prev       = response[i]
 *
 * The chain dependency (prev) means every byte of the response depends on
 * all previous bytes. The rotate prevents simple algebraic cancellation.
 * The second PUF index folds more physical state into each byte.
 */
void derive_expected_response(uint8_t* stored_puf, uint8_t* challenge, uint8_t* expected) {
  uint8_t prev = 0x5A;  // Must match Arduino's seed exactly
  for (uint16_t i = 0; i < CHALLENGE_SIZE; i++) {
    // Mirror the Arduino: hash the challenge only so noise doesn't avalanche
    uint8_t rotated_prev = (prev << 3) | (prev >> 5);
    uint8_t c_mix = challenge[i] ^ rotated_prev;
    
    expected[i] = c_mix ^ stored_puf[i];
    prev = c_mix;
  }
}

// ─── Storage ──────────────────────────────────────────────────────────────────

/*
 * store_puf()
 *
 * Stores the stabilized PUF reference and stability mask in NVS under the
 * "ghostkey" namespace. Both must be loaded together for authentication.
 */
void store_puf(uint8_t* puf, uint8_t* mask) {
  prefs.begin("ghostkey", false);
  prefs.putBytes("puf",      puf,  PUF_SIZE);
  prefs.putBytes("mask",     mask, PUF_SIZE);
  prefs.putBool("enrolled",  true);
  prefs.end();
}

/*
 * load_puf()
 *
 * Loads the stabilized PUF and stability mask from NVS.
 * Returns false if the device is not enrolled.
 *
 * If "mask" key is absent (e.g. NVS was written by an older firmware version
 * without mask support), mask_out is filled with 0xFF (all bits stable) so
 * authentication degrades gracefully to full Hamming distance.
 */
bool load_puf(uint8_t* puf_out, uint8_t* mask_out) {
  prefs.begin("ghostkey", true);
  bool enrolled = prefs.getBool("enrolled", false);
  if (enrolled) {
    prefs.getBytes("puf", puf_out, PUF_SIZE);
    size_t mask_len = prefs.getBytes("mask", mask_out, PUF_SIZE);
    if (mask_len == 0) {
      // Legacy enrollment without mask: treat all bits as stable
      memset(mask_out, 0xFF, PUF_SIZE);
    }
  }
  prefs.end();
  return enrolled;
}

bool is_enrolled() {
  prefs.begin("ghostkey", true);
  bool e = prefs.getBool("enrolled", false);
  prefs.end();
  return e;
}

/*
 * wipe_enrollment()
 *
 * Called on tamper detection. Deletes the stored PUF from NVS.
 * Without it, the ESP32 has no reference to derive expected responses from,
 * so every authentication fails. The firmware stays intact (bouncer stays,
 * guest list is shredded — see doc Section 2.5).
 */
void wipe_enrollment() {
  prefs.begin("ghostkey", false);
  prefs.clear();
  prefs.end();
  Serial.println("!!! ENROLLMENT WIPED — SYSTEM LOCKED !!!");
}

// ─── Tamper Detection ─────────────────────────────────────────────────────────

/*
 * check_tamper()
 *
 * Polls all three tamper sensors every loop iteration.
 * Any trigger immediately wipes enrollment and locks the system.
 *
 * LDR (GPIO34):   HIGH = light detected = enclosure opened.
 *                 Threshold: analogRead > 2000 (calibrate for your enclosure).
 * Vibration (GPIO35): LOW = vibration event on SW-420 (active-low module).
 * Voltage (GPIO36):   LOW = comparator fired = power rail anomaly detected.
 *
 * CALIBRATION NOTE: The vibration threshold and LDR threshold should be tuned
 * during testing so normal handling doesn't cause false positives. The LDR
 * reading depends heavily on your enclosure and ambient conditions.
 */
void check_tamper() {
  if (tamper_triggered) return;
  //if (millis() < tamper_armed_at) return;
  //if (millis() - last_button_press < VIBRATION_COOLDOWN_MS) return; 

  // LDR — light in enclosure
  int ldr_val = analogRead(PIN_LDR);
  if (ldr_val > 50) {
    trigger_tamper("LIGHT_DETECTED");
    return;
  }

   ///Vibration — active-low (SW-420 DO pin pulls LOW on vibration)
  //if (digitalRead(PIN_VIBRATION) == LOW) {
    //uint32_t low_start = millis();
  
    //while (digitalRead(PIN_VIBRATION) == LOW && millis() - low_start < 200) {
    //delay(1);
    //}
  
    //int32_t low_duration = millis() - low_start;

    // A button press causes a very brief LOW (< 20ms)
    // Sustained handling of the enclosure holds LOW much longer
    //if (low_duration > 199) {
      //trigger_tamper("VIBRATION");
      //Serial.print(low_duration);
      //return;
  //}

  // Voltage comparator — active-low on trigger
  if (digitalRead(PIN_VOLTAGE) == LOW) {
    trigger_tamper("VOLTAGE_GLITCH");
    return;
  }
}

void trigger_tamper(const char* reason) {
  tamper_triggered = true;
  Serial.print("!!! TAMPER DETECTED: ");
  Serial.println(reason);
  update_display("!!! TAMPER !!!", "System Locked", reason);
  wipe_enrollment();
  digitalWrite(PIN_RELAY, LOW);   // Ensure lock stays locked
  set_led(true, false, false);    // Solid red
}

// ─── Communication Helpers ────────────────────────────────────────────────────

/*
 * wait_for_ready()
 *
 * Listens for "GHOSTKEY_READY" from the Arduino within timeout_ms.
 * Handles garbage bytes at startup by only looking at printable ASCII.
 */
bool wait_for_ready(uint32_t timeout_ms) {
  uint32_t start = millis();
  String line = "";
  while (millis() - start < timeout_ms) {
    while (Serial2.available()) {
      char c = (char)Serial2.read();
      if (c == '\n') {
        line.trim();
        if (line.endsWith("GHOSTKEY_READY")) return true;
        line = "";
      } else if (c >= 32 && c <= 126) {
        line += c;
      }
    }
    delay(10);
  }
  return false;
}

/*
 * send_challenge_get_response()
 *
 * Sends "CHALLENGE:<hex>\n" and waits up to 3 seconds for "RESPONSE:<hex>\n".
 * Parses the response hex into response_out[].
 */
bool send_challenge_get_response(uint8_t* challenge, uint8_t* response_out) {
  // discard any stale bytes (e.g. GHOSTKEY_READY heartbeats)
  while (Serial2.available()) Serial2.read();

  send_hex_command("CHALLENGE:", challenge, CHALLENGE_SIZE);

  uint32_t start = millis();
  String line = "";

  while (millis() - start < 5000) {
    while (Serial2.available()) {
      char c = (char)Serial2.read();
      if (c == '\n') {
        line.trim();
        if (line.startsWith("RESPONSE:")) {
          String hex_data = line.substring(9);
          return parse_hex_to_bytes(hex_data, response_out, CHALLENGE_SIZE);
        }
        if (line.startsWith("ERROR:")) {
          Serial.print("Arduino error: "); Serial.println(line);
          return false;
        }
        line = "";
      } else if (c >= 32 && c <= 126) {
        line += c;
      }
    }
    delay(10);
  }
  return false;
}

/*
 * send_hex_command()
 *
 * Sends "<prefix><hex_data>\n" over Serial2.
 * e.g. "CHALLENGE:A3F2...\n"
 */
void send_hex_command(const char* prefix, uint8_t* data, uint16_t len) {
  Serial2.print(prefix);
  for (uint16_t i = 0; i < len; i++) {
    if (data[i] < 0x10) Serial2.print("0");
    Serial2.print(data[i], HEX);
  }
  Serial2.println();
}

bool parse_hex_to_bytes(String hex_str, uint8_t* out, uint16_t expected_len) {
  if (hex_str.length() < (uint32_t)(expected_len * 2)) return false;
  for (uint16_t i = 0; i < expected_len; i++) {
    char buf[3] = { hex_str[i * 2], hex_str[i * 2 + 1], '\0' };
    out[i] = (uint8_t)strtol(buf, NULL, 16);
  }
  return true;
}

// ─── Output Helpers ───────────────────────────────────────────────────────────

void set_led(bool r, bool g, bool b) {
  digitalWrite(PIN_LED_RED,   r ? HIGH : LOW);
  digitalWrite(PIN_LED_GREEN, g ? HIGH : LOW);
  digitalWrite(PIN_LED_BLUE,  b ? HIGH : LOW);
}

void open_relay() {
  digitalWrite(PIN_RELAY, HIGH);
  uint32_t start = millis();
  while (millis() - start < RELAY_OPEN_MS) {
    // Wait for button release during relay open window
    if (digitalRead(PIN_AUTH_BTN) == HIGH) break;
    delay(10);
  }
  digitalWrite(PIN_RELAY, LOW);
}

void print_puf(uint8_t* fp) {
  for (int i = 0; i < PUF_SIZE; i++) {
    if (fp[i] < 0x10) Serial.print("0");
    Serial.print(fp[i], HEX);
  }
  Serial.println();
}

// ─── Hamming Distance ─────────────────────────────────────────────────────────

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

/*
 * masked_hamming_distance()
 *
 * Computes the Hamming distance between arrays a[] and b[], but only counts
 * bit positions where the corresponding mask bit is 1 (stable). Bit positions
 * with mask bit 0 (unstable during enrollment) are silently skipped — they
 * contribute neither to the distance nor to the total bit count.
 *
 * This ensures that SRAM bits known to be noisy across power cycles cannot
 * cause false rejections of the legitimate Arduino.
 *
 * Parameters:
 *   a, b  — response arrays to compare (both CHALLENGE_SIZE bytes)
 *   mask  — stability mask from enrollment (PUF_SIZE bytes, must == CHALLENGE_SIZE)
 *   len   — number of bytes (CHALLENGE_SIZE)
 *
 * Returns: number of differing stable bits.
 */
uint16_t masked_hamming_distance(uint8_t* a, uint8_t* b, uint8_t* mask, uint16_t len) {
  uint16_t d = 0;
  for (uint16_t byte_i = 0; byte_i < len; byte_i++) {
    uint8_t diff = a[byte_i] ^ b[byte_i];
    // Only count differing bits that are masked as stable
    uint8_t masked_diff = diff & mask[byte_i];
    d += hamming_distance_byte(masked_diff, 0);
  }
  return d;
}
