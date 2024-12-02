| Supported Targets | ESP32 | ESP32-S3 | ESP32-C3 | ESP32-C5 | ESP32-C6 |
| ----------------- | ----- | -------- | -------- | -------- | -------- |

# ECDSA sign/verify Example with ESP32 series SoC interfaced with ATECC608A

## Description

(See the README.md file in the upper level 'examples' directory for more information about examples.)

This example requires ESP32 platform interfaced with Microchip's [ATECC608A](https://www.microchip.com/wwwproducts/en/ATECC608A) Secure Element.

For making the hardware connections with `ATECC608A` chip (Secure Element), please refer [this](https://github.com/espressif/esp-cryptoauthlib/blob/master/esp_cryptoauth_utility/README.md#using-atecc608a-with-esp32-wroom-32) for details.

The example performs `ECDSA sign/verify` functions on sample data using hardware private key stored in ATECC608A chip.

## How to use example

Before project configuration and build, be sure to set the correct chip target using `idf.py set-target <chip_name>`.

### Hardware Required

* A development board with ESP32 series based SoC
* `ATECC608A` IC based external module or dev. board.
* A USB cable for Power supply and programming

### Configure the project

Hardware should be configured to run the example, for details on configuration of ATECC608A chip, please refer [esp_cryptoauth_utility](https://github.com/espressif/esp-cryptoauthlib/blob/master/esp_cryptoauth_utility/README.md#esp_cryptoauth_utility)

Open the project configuration menu (`idf.py menuconfig`). 

In the `Component config -> esp-cryptoauthlib` menu:

* Use `Choose the type of ATECC608A chip` to set the Crypto IC type [1].
* Use `Enable Hardware ECDSA keys for mbedTLS` Enable Hardware ECDSA.
    * Set `Enable ATECC608A sign operations in mbedTLS` to use Hardware ECDSA sign.
    * Set `Enable ATECC608A verify operations in mbedTLS` to use Hardware ECDSA verify.
* Set `I2C SDA pin used to communicate with the ATECC608A`.
* Set `I2C SCL pin used to communicate with the ATECC608A`.

[1]: for more details refer [Find ATECC608A chip type](https://github.com/espressif/esp-cryptoauthlib/blob/master/esp_cryptoauth_utility/README.md).

### Build and Flash

Build the project and flash it to the board, then run the monitor tool to view the serial output:

Run `idf.py -p PORT flash monitor` to build, flash and monitor the project.

(To exit the serial monitor, type ``Ctrl-]``.)

See the [Getting Started Guide](https://docs.espressif.com/projects/esp-idf/en/latest/get-started/index.html) for all the steps to configure and use the ESP-IDF to build projects.

## Troubleshooting

For any technical queries, please open an [issue](https://github.com/espressif/esp-idf/issues) on GitHub. We will get back to you soon.
