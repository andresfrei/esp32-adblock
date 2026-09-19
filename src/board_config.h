#pragma once

// Board-specific controls stay here so the C3 behavior remains unchanged while
// the provisional S3 port does not guess at a destructive GPIO function.
#if defined(ARDUINO_ESP32S3_DEV) || defined(CONFIG_IDF_TARGET_ESP32S3)
#define AD_BLOCK_BOARD_LABEL "esp32-s3-n16r8-provisional"
#define AD_BLOCK_BOOT_PIN 0                 // conventional S3 BOOT GPIO; unverified
#if defined(S3_ENABLE_BOOT_WIFI_RESET)
#define AD_BLOCK_BOOT_RESET_ENABLED 1       // explicit opt-in only
#else
#define AD_BLOCK_BOOT_RESET_ENABLED 0
#endif
#define AD_BLOCK_NETWORK_PROFILE_ENABLED 1  // S3-only transactional network UI
#elif defined(ARDUINO_ESP32C3_DEV) || defined(CONFIG_IDF_TARGET_ESP32C3)
#define AD_BLOCK_BOARD_LABEL "esp32-c3"
#define AD_BLOCK_BOOT_PIN 9
#define AD_BLOCK_BOOT_RESET_ENABLED 1
#define AD_BLOCK_NETWORK_PROFILE_ENABLED 0
#else
#define AD_BLOCK_NETWORK_PROFILE_ENABLED 0
#define AD_BLOCK_BOARD_LABEL "esp32-unknown"
#define AD_BLOCK_BOOT_PIN 0
#define AD_BLOCK_BOOT_RESET_ENABLED 0
#endif
