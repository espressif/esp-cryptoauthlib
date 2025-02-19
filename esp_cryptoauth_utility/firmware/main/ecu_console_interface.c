/*
 * Copyright 2025 Espressif Systems (Shanghai) CO LTD
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <string.h>
#include "ecu_console_interface.h"
#include "esp_log.h"
#include "esp_err.h"

#if SOC_UART_SUPPORTED
#include <driver/uart.h>
#endif

#if SOC_USB_SERIAL_JTAG_SUPPORTED
#include "driver/usb_serial_jtag.h"
#endif

static const char *TAG = "ECU Console Interface";
static ecu_console_interface_t *console_interface = NULL;
#define ECU_CONSOLE_INTERFACE_TX_BUFFER_SIZE 2048
#define ECU_CONSOLE_INTERFACE_RX_BUFFER_SIZE 2048
#define ECU_CONSOLE_INTERFACE_TIMEOUT 500

#if SOC_UART_SUPPORTED
#define ECU_UART_NUM UART_NUM_0
#define ECU_UART_INTR_ALLOC_FLAGS 0
static esp_err_t uart_install()
{
    return uart_driver_install(ECU_UART_NUM, ECU_CONSOLE_INTERFACE_RX_BUFFER_SIZE, ECU_CONSOLE_INTERFACE_TX_BUFFER_SIZE, 0, NULL, 0);
}

static esp_err_t uart_uninstall()
{
    return uart_driver_delete(ECU_UART_NUM);
}

static int uart_read(uint8_t *buf, size_t length, TickType_t ticks_to_wait)
{
    return uart_read_bytes(ECU_UART_NUM, buf, length, ticks_to_wait);
}

static int uart_write(const char *buf, size_t length, TickType_t ticks_to_wait)
{
    return uart_write_bytes(ECU_UART_NUM, buf, length); // Added ticks_to_wait
}
static esp_err_t ecu_uart_wait_tx_done(TickType_t ticks_to_wait)
{
    return uart_wait_tx_done(ECU_UART_NUM, ticks_to_wait);
}
#endif

ecu_console_interface_t ecu_console_interface_uart = {
#if SOC_UART_SUPPORTED
    .type = ECU_CONSOLE_INTERFACE_UART,
    .install = uart_install,
    .uninstall = uart_uninstall,
    .read_bytes = uart_read,
    .write_bytes = uart_write,
    .wait_tx_done = ecu_uart_wait_tx_done,
#else
    .type = ECU_CONSOLE_INTERFACE_NONE,
#endif
};

#if SOC_USB_SERIAL_JTAG_SUPPORTED
static esp_err_t usb_serial_install() {
    usb_serial_jtag_driver_config_t jtag_config = {
        .tx_buffer_size = ECU_CONSOLE_INTERFACE_TX_BUFFER_SIZE,
        .rx_buffer_size = ECU_CONSOLE_INTERFACE_RX_BUFFER_SIZE,
    };
    return usb_serial_jtag_driver_install(&jtag_config);
}

static int usb_serial_read(uint8_t *buf, size_t length, TickType_t ticks_to_wait)
{
    return usb_serial_jtag_read_bytes(buf, length, ticks_to_wait);
}

static int usb_serial_write(const char *buf, size_t length, TickType_t ticks_to_wait)
{
    return usb_serial_jtag_write_bytes(buf, length, ticks_to_wait);
}

static esp_err_t usb_serial_uninstall()
{
    return usb_serial_jtag_driver_uninstall();
}
static esp_err_t ecu_usb_serial_wait_tx_done(TickType_t ticks_to_wait)
{
    return usb_serial_jtag_wait_tx_done(ticks_to_wait);
}
#endif

ecu_console_interface_t ecu_console_interface_usb = {
#if SOC_USB_SERIAL_JTAG_SUPPORTED
    .type = ECU_CONSOLE_INTERFACE_USB,
    .install = usb_serial_install,
    .uninstall = usb_serial_uninstall,
    .read_bytes = usb_serial_read,
    .write_bytes = usb_serial_write,
    .wait_tx_done = ecu_usb_serial_wait_tx_done,
#else
    .type = ECU_CONSOLE_INTERFACE_NONE,
#endif
};

void print_console_interface(void)
{
    if (console_interface != NULL) {
        if (console_interface->type == ECU_CONSOLE_INTERFACE_UART) {
            ESP_LOGI(TAG, "Console is running on UART0");
        } else if (console_interface->type == ECU_CONSOLE_INTERFACE_USB) {
            ESP_LOGI(TAG, "Console is running on USB Serial JTAG");
        }
    } else {
        ESP_LOGI(TAG, "No console interface is configured");
    }
}

esp_err_t ecu_initialize_console_interface(void)
{
    esp_err_t esp_ret = ESP_FAIL;
    int ret = 0;
    char linebuf[8];

    ESP_LOGI(TAG, "Free heap: %ld bytes", esp_get_free_heap_size());

#if SOC_USB_SERIAL_JTAG_SUPPORTED
    console_interface = &ecu_console_interface_usb;
    esp_ret = console_interface->install();
    if (esp_ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to install USB Serial JTAG driver");
        return esp_ret;
    }
    bzero(linebuf, sizeof(linebuf));
    printf("Initializing Command line: >>");
    ret = console_interface->read_bytes((uint8_t *)linebuf, strlen("version"), pdMS_TO_TICKS(ECU_CONSOLE_INTERFACE_TIMEOUT));  // Adjust size for "version"
    if (ret == strlen("version")) {
        if (memcmp(linebuf, "version", strlen("version")) == 0) {
            printf("%s\n", PROJECT_VER);
            ESP_LOGI(TAG, "USB Serial JTAG interface successfully initialized");
            return ESP_OK;
        }
    }
    esp_ret = console_interface->uninstall();
    if (esp_ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to uninstall USB Serial JTAG driver");
        return esp_ret;
    }
#endif

#if SOC_UART_SUPPORTED
    console_interface = &ecu_console_interface_uart;
    esp_ret = console_interface->install();
    if (esp_ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to install UART driver");
        return esp_ret;
    }
    bzero(linebuf, sizeof(linebuf));
    printf("Initializing Command line: >>");
    ret = console_interface->read_bytes((uint8_t *)linebuf, strlen("version"), pdMS_TO_TICKS(ECU_CONSOLE_INTERFACE_TIMEOUT));  // Adjust size for "version"
    if (ret == strlen("version")) {
        if (memcmp(linebuf, "version", strlen("version")) == 0) {
            printf("%s\n", PROJECT_VER);
            ESP_LOGI(TAG, "UART interface successfully initialized");
            return ESP_OK;
        }
    }
    esp_ret = console_interface->uninstall();
    if (esp_ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to uninstall UART driver");
        return esp_ret;
    }
#endif

    ESP_LOGE(TAG, "Failed to initialize ECU console interface");
    return ESP_FAIL;
}

ecu_console_interface_t *get_console_interface(void)
{
    if (console_interface == NULL) {
        ESP_LOGE(TAG, "Console interface is not initialized");
        return NULL;
    }
    return console_interface;
}
