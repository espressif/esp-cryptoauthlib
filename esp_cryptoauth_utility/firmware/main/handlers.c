/*
 * Copyright 2021 Espressif Systems (Shanghai) CO LTD
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
#ifdef CONFIG_ECU_DEBUGGING
#define ECU_DEBUG_LOG ESP_LOGI
#else
#define ECU_DEBUG_LOG(...)
#endif /* MFG_DEBUG */

#include <string.h>
#include "stdio.h"
#include "mbedtls/config.h"
#include "mbedtls/platform.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/base64.h"

#include "esp_log.h"
#include "esp_err.h"
#include "esp_partition.h"
#include "esp_flash_partitions.h"
#include "esp_spi_flash.h"
#include "driver/uart.h"

#include "handlers.h"

/* Cryptoauthlib includes */
#include "cryptoauthlib.h"
#include "cert_def_3_device_csr.h"
#include "cert_def_2_device.h"
#include "cert_def_1_signer.h"
#include "atcacert/atcacert_client.h"
#include "atcacert/atcacert_pem.h"
#include "tng_atcacert_client.h"
#include "hal_esp32_i2c.h"

#include "mbedtls/atca_mbedtls_wrap.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"

static const char *TAG = "secure_element";
static bool is_atcab_init = false;

extern QueueHandle_t uart_queue;

static atcacert_def_t g_cert_def_common;
uint8_t *g_cert_template_device;

static const uint8_t public_key_x509_header[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04
};


int convert_pem_to_der( const unsigned char *input, size_t ilen,
                        unsigned char *output, size_t *olen )
{
    int ret;
    const unsigned char *s1, *s2, *end = input + ilen;
    size_t len = 0;

    s1 = (unsigned char *) strstr( (const char *) input, "-----BEGIN" );
    if ( s1 == NULL ) {
        return ( -1 );
    }

    s2 = (unsigned char *) strstr( (const char *) input, "-----END" );
    if ( s2 == NULL ) {
        return ( -1 );
    }

    s1 += 10;
    while ( s1 < end && *s1 != '-' ) {
        s1++;
    }
    while ( s1 < end && *s1 == '-' ) {
        s1++;
    }
    if ( *s1 == '\r' ) {
        s1++;
    }
    if ( *s1 == '\n' ) {
        s1++;
    }

    if ( s2 <= s1 || s2 > end ) {
        return ( -1 );
    }
    ret = mbedtls_base64_decode( NULL, 0, &len, (const unsigned char *) s1, s2 - s1 );
    if ( ret == MBEDTLS_ERR_BASE64_INVALID_CHARACTER ) {
        return ( ret );
    }

    if ( len > *olen ) {
        return ( -1 );
    }
    if ( ( ret = mbedtls_base64_decode( output, len, &len, (const unsigned char *) s1,
                                        s2 - s1 ) ) != 0 ) {
        return ( ret );
    }

    *olen = len;

    return ( 0 );
}

esp_err_t init_atecc608a(char *device_type, uint8_t i2c_sda_pin, uint8_t i2c_scl_pin, int *err_ret)
{
    int ret = 0;
    bool is_zone_locked = false;
    ECU_DEBUG_LOG(TAG, "initialize the ATECC interface...");
    sprintf(device_type, "%s", "TrustCustom");
    hal_esp32_i2c0_set_pin_config(i2c_sda_pin,i2c_scl_pin);
    ESP_LOGI(TAG, "debug - I2C pins selected are SDA = %d, SCL = %d", i2c_sda_pin, i2c_scl_pin);

    if (ATCA_SUCCESS != (ret = atcab_init(&cfg_ateccx08a_i2c_default))) {
        sprintf(device_type, "%s", "Trust&Go");
        /* Checking if the ATECC608 is of type Trust & GO */
        cfg_ateccx08a_i2c_default.atcai2c.address = 0x6A;
        printf("\nnot trustngo\n");
        if (ATCA_SUCCESS != (ret = atcab_init(&cfg_ateccx08a_i2c_default))) {
            sprintf(device_type, "%s", "TrustFlex");
            /* Checking if the ATECC608 is of type TrustFlex */
            cfg_ateccx08a_i2c_default.atcai2c.address = 0x6C;
            printf("\nnot trustflex\n");

            if (ATCA_SUCCESS != (ret = atcab_init(&cfg_ateccx08a_i2c_default))) {
                ESP_LOGE(TAG, " failed\n  ! atcab_init returned %02x", ret);
                goto exit;
            }

        }

    } else {
        ESP_LOGE(TAG, " failed\n  ! atcab_init returned %02x", ret);
        goto exit;
    }

    ECU_DEBUG_LOG(TAG, "\t\t OK");

    if (ATCA_SUCCESS != (ret = atcab_is_locked(LOCK_ZONE_CONFIG, &is_zone_locked))) {
        ESP_LOGE(TAG, " failed\n  ! atcab_is_locked returned %02x", ret);
        goto exit;
    }

    if (!is_zone_locked) {
        ret = atcab_lock_config_zone();
        if (ret != ATCA_SUCCESS) {
            ESP_LOGE(TAG, "error in locking config zone, ret = %02x", ret);
            goto exit;
        }
        ECU_DEBUG_LOG(TAG, "success in locking config zone");
    } else {
        ECU_DEBUG_LOG(TAG, "config zone is Locked ..\tOK");
    }

    is_zone_locked = false;

    if (ATCA_SUCCESS != (ret = atcab_is_locked(LOCK_ZONE_DATA, &is_zone_locked))) {
        ESP_LOGE(TAG, " failed\n  ! atcab_is_locked returned %02x", ret);
        goto exit;
    }

    if (!is_zone_locked) {
        ret = atcab_lock_data_zone();
        if (ret != ATCA_SUCCESS) {
            ESP_LOGE(TAG, "\nerror in locking data zone, ret = %02x", ret);
            goto exit;
        }
        ECU_DEBUG_LOG(TAG, "success in locking data zone");
    } else {
        ECU_DEBUG_LOG(TAG, "data zone is Locked ..\tOK");
    }
    is_atcab_init = true;
    *err_ret = ret;
    return ESP_OK;
exit:
    *err_ret = ret;
    return ESP_FAIL;
}

esp_err_t atecc_print_info(uint8_t *serial_no, int *err_ret)
{
    uint8_t rev_info[4] = {};
    int ret = -1;
    if (ATCA_SUCCESS != (ret = atcab_info(rev_info))) {
        ESP_LOGE(TAG, "Error in reading revision information, ret is %02x", ret);
        goto exit;
    }
    ESP_LOG_BUFFER_HEX("ATECC CHIP REVISION", rev_info, 4);
    if (rev_info[3] == 0x03) {
        ESP_LOGI(TAG, "Since the last byte of chip revision is 0x03. This is an ATECC608B chip");
    } else if (rev_info[3] == 0x02) {
        ESP_LOGI(TAG, "Since the last byte of chip revision is 0x02. This is a ATECC608A chip");
    }

    if (ATCA_SUCCESS != (ret = atcab_read_serial_number(serial_no))) {
        ESP_LOGE(TAG, "Error in reading serial number, ret is %02x", ret);
        goto exit;
    }
    ESP_LOG_BUFFER_HEX("ATECC CHIP SERIAL NUMBER", serial_no, 9);
    *err_ret = ret;
    return ESP_OK;
exit:
    *err_ret = ret;
    return ESP_FAIL;
}

static void print_public_key(uint8_t pubkey[ATCA_PUB_KEY_SIZE])
{
    uint8_t buf[128];
    uint8_t *tmp;
    size_t buf_len = sizeof(buf);

    /* Calculate where the raw data will fit into the buffer */
    tmp = buf + sizeof(buf) - ATCA_PUB_KEY_SIZE - sizeof(public_key_x509_header);

    /* Copy the header */
    memcpy(tmp, public_key_x509_header, sizeof(public_key_x509_header));

    /* Copy the key bytes */
    memcpy(tmp + sizeof(public_key_x509_header), pubkey, ATCA_PUB_KEY_SIZE);

    /* Convert to base 64 */
    (void)atcab_base64encode(tmp, ATCA_PUB_KEY_SIZE + sizeof(public_key_x509_header), (char *)buf, &buf_len);

    /* Add a null terminator */
    buf[buf_len] = 0;

    /* Print out the key */
    ECU_DEBUG_LOG(TAG, "\r\n-----BEGIN PUBLIC KEY-----\r\n%s\r\n-----END PUBLIC KEY-----\r\n", buf);
}

esp_err_t atecc_keygen(int slot, unsigned char *pub_key_buf, int pub_key_buf_len, int *err_ret)
{
    int ret = 0;
    bzero(pub_key_buf, pub_key_buf_len);
    if (!is_atcab_init) {
        ESP_LOGE(TAG, "gevice is not initialized");
        goto exit;
    }
    ECU_DEBUG_LOG(TAG, "generating priv key ..");

    if (ATCA_SUCCESS != (ret = atcab_genkey(slot, pub_key_buf))) {
        ESP_LOGE(TAG, "failed\n !atcab_genkey returned -0x%02x", -ret);
        goto exit;
    }
    ECU_DEBUG_LOG(TAG, "\t\t OK");
    print_public_key(pub_key_buf);
    *err_ret = ret;
    return ESP_OK;

exit:
    ESP_LOGE(TAG, "failure in generating Key");
    *err_ret = ret;
    return ESP_FAIL;
}

esp_err_t atecc_gen_pubkey(int slot, unsigned char *pub_key_buf, int pub_key_buf_len, int *err_ret)
{
    int ret = -1;
    if (!is_atcab_init) {
        ESP_LOGE(TAG, "\ndevice is not initialized");
        goto exit;
    }
    bzero(pub_key_buf, pub_key_buf_len);
    ECU_DEBUG_LOG(TAG, "Get the public key...");
    if (0 != (ret = atcab_get_pubkey(slot, pub_key_buf))) {
        ESP_LOGE(TAG, " failed\n  ! atcab_get_pubkey returned %02x", ret);
        goto exit;
    }
    ECU_DEBUG_LOG("\t\t OK\n");
    print_public_key(pub_key_buf);
    *err_ret = ret;
    return ESP_OK;

exit:
    *err_ret = ret;
    ESP_LOGE(TAG, "\ngenerate public key failed");
    return ESP_FAIL;
}

esp_err_t atecc_csr_gen(unsigned char *csr_buf, size_t csr_buf_len, int *err_ret)
{
    int ret = 0;
    if (!is_atcab_init) {
        ESP_LOGE(TAG, "device is not initialized");
        goto exit;
    }
    bzero(csr_buf, csr_buf_len);
    ECU_DEBUG_LOG(TAG, "generating csr ..");
    ret = atcacert_create_csr_pem(&g_csr_def_3_device, (char *)csr_buf, &csr_buf_len);
    if (ret != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "create csr pem failed, returned %02x", ret);
        goto exit;
    }
    ECU_DEBUG_LOG(TAG, "\t\t OK");
    *err_ret = ret;
    return ESP_OK;

exit:
    ESP_LOGE(TAG, "Failure, Exiting , ret is %02x", ret);
    *err_ret = ret;
    return ESP_FAIL;

}

esp_err_t get_cert_def(unsigned char *cert_def_array, size_t data_len, cert_type_t cert_type)
{
    if (cert_type == CERT_TYPE_DEVICE) {
        g_cert_def_common = g_cert_def_2_device;
    } else if (cert_type == CERT_TYPE_SIGNER) {
        g_cert_def_common = g_cert_def_1_signer;
    }
    int uart_num = 0, i = 0;
    esp_err_t ret;
    uart_event_t event;

    memset(cert_def_array, 0xff, data_len);
    do {
        ret = xQueueReceive(uart_queue, (void * )&event, (portTickType) portMAX_DELAY);
        if (ret != pdPASS) {
            continue;
        }

        if (event.type == UART_DATA) {
            while (uart_read_bytes(uart_num, (uint8_t *) &cert_def_array[i], 1, 0)) {
                if (cert_def_array[i] == '\0') {
                    break;
                }
                i++;
            }
        }
    } while (i < data_len - 1 && cert_def_array[i] != '\0');

    char str[4] = {};
    int count = 0;
    /* converting the offsets and counts to int, 4 bytes at a time */
    for (count = 0 ; count < 8; count++) {
        memcpy(str, &cert_def_array[4 * ((2 * count) + 0)], 4);
        g_cert_def_common.std_cert_elements[count].offset = (uint16_t)atoi(str);
        memcpy(str, &cert_def_array[4 * ((2 * count) + 1)], 4);
        g_cert_def_common.std_cert_elements[count].count = (uint16_t)atoi(str);
    }

    memcpy(str, &cert_def_array[4 * ((2 * count) + 0)], 4);
    g_cert_def_common.tbs_cert_loc.offset = (uint16_t)atoi(str);

    memcpy(str, &cert_def_array[4 * ((2 * count) + 1)], 4);
    g_cert_def_common.tbs_cert_loc.count = (uint16_t)atoi(str);

    count = count + 1;
    /* converting to total number of bytes used */
    count = count * 8;
    int template_size = ((strlen((const char *)&cert_def_array[0]) - count ) / 2);
    int pos = 0;
    char temp[2];
    g_cert_template_device = (uint8_t *)calloc(sizeof(uint8_t), template_size);
    /* Converting the templates from string to hex, 2 bytes at a time */
    for (int i = 0; i < template_size; i++) {
        memcpy(temp, &cert_def_array[count], 2);
        g_cert_template_device[pos] = strtol((const char *)temp, NULL, 16);
        pos ++;
        count = count + 2;
    }
    atcacert_cert_element_t *cert_element;

    cert_element =  (atcacert_cert_element_t *)calloc(sizeof(atcacert_cert_element_t), 2);

    if (cert_type == CERT_TYPE_SIGNER) {
        cert_element[0].device_loc.offset = 35 - g_cert_def_common.std_cert_elements[STDCERT_ISSUE_DATE].offset;
        cert_element[0].device_loc.count = g_cert_def_common.std_cert_elements[STDCERT_ISSUE_DATE].count;
        cert_element[0].cert_loc.offset = g_cert_def_common.std_cert_elements[STDCERT_ISSUE_DATE].offset;
        cert_element[0].cert_loc.count = g_cert_def_common.std_cert_elements[STDCERT_ISSUE_DATE].count;

        cert_element[1].device_loc.offset = 50 - g_cert_def_common.std_cert_elements[STDCERT_EXPIRE_DATE].offset;
        cert_element[1].device_loc.count = g_cert_def_common.std_cert_elements[STDCERT_EXPIRE_DATE].count;
        cert_element[1].cert_loc.offset = g_cert_def_common.std_cert_elements[STDCERT_EXPIRE_DATE].offset;
        cert_element[1].cert_loc.count = g_cert_def_common.std_cert_elements[STDCERT_EXPIRE_DATE].count;

        g_cert_def_common.cert_elements = cert_element;
        g_cert_def_common.cert_elements_count = 2;
    }

    g_cert_def_common.cert_template = g_cert_template_device;
    g_cert_def_common.cert_template_size = template_size;

    return ESP_OK;
}

esp_err_t atecc_input_cert(unsigned char *cert_buf, size_t cert_len, cert_type_t cert_type, int *err_ret)
{
    int ret = -1;

    if (!is_atcab_init) {
        ESP_LOGE(TAG, "\ndevice is not initialized");
        goto exit;
    }
    int uart_num = 0, i = 0;
    uart_event_t event;

    memset(cert_buf, 0xff, cert_len);
    do {
        ret = xQueueReceive(uart_queue, (void * )&event, (portTickType) portMAX_DELAY);
        if (ret != pdPASS) {
            continue;
        }

        if (event.type == UART_DATA) {
            while (uart_read_bytes(uart_num, (uint8_t *) &cert_buf[i], 1, 0)) {
                if (cert_buf[i] == '\0') {
                    break;
                }
                i++;
            }
        }
    } while (i < cert_len - 1 && cert_buf[i] != '\0');

    uint8_t der_cert[800];
    size_t der_cert_size = 800;
    if (convert_pem_to_der(cert_buf, cert_len, (unsigned char *)der_cert, &der_cert_size) != 0) {
        ESP_LOGE(TAG, "error in converting to der");
        return ESP_FAIL;
    }

    der_cert[der_cert_size] = 0;
    der_cert_size += 1;

    if (cert_type == CERT_TYPE_DEVICE) {
        ECU_DEBUG_LOG(TAG, "writing device cert ..");
        ;
        if (ATCA_SUCCESS != (ret = atcacert_write_cert((const atcacert_def_t *)&g_cert_def_common, der_cert, der_cert_size + 1))) {
            ESP_LOGE(TAG, "writecert failed , ret is %02x", ret);
            goto exit;
        }
    } else if (cert_type == CERT_TYPE_SIGNER) {
        ECU_DEBUG_LOG(TAG, "writing signer cert ..");
        ;
        if (ATCA_SUCCESS != (ret = atcacert_write_cert(&g_cert_def_common, der_cert, der_cert_size + 1))) {
            ESP_LOGE(TAG, "writecert failed , ret is %02x", ret);
            goto exit;
        }
    } else {
        ESP_LOGE(TAG, "wrong cert type");
        goto exit;
    }
    ECU_DEBUG_LOG(TAG, "\t\t OK");
    *err_ret = ret;
    return ESP_OK;
exit:
    ESP_LOGE(TAG, "failure, exiting");
    *err_ret = ret;
    return ESP_FAIL;
}

esp_err_t atecc_get_tngtls_root_cert(unsigned char *cert_buf, size_t *cert_len, int *err_ret)
{
    int ret;
    ECU_DEBUG_LOG(TAG, "atecc_get_tngtls_root_cert start");
    if (ATCA_SUCCESS != (ret = tng_atcacert_root_cert_size(cert_len))) {
        ESP_LOGE(TAG, "failed to get tng_atcacert_root_cert_size, returned 0x%02x", ret);
        goto exit;
    }
    if (ATCA_SUCCESS != (ret = tng_atcacert_root_cert(cert_buf, cert_len))) {
        ESP_LOGE(TAG, "failed to read tng_atcacert_root_cert, returned 0x%02x", ret);
        goto exit;
    }
    ECU_DEBUG_LOG(TAG, "atecc_get_tngtls_root_cert end");
    *err_ret = ret;
    return ESP_OK;

exit:
    *err_ret = ret;
    return ESP_FAIL;
}

esp_err_t atecc_get_tngtls_signer_cert(unsigned char *cert_buf, size_t *cert_len, int *err_ret)
{
    int ret;
    ECU_DEBUG_LOG(TAG, "atecc_get_tngtls_signer_cert start");
    if (ATCA_SUCCESS != (ret = tng_atcacert_max_signer_cert_size(cert_len))) {
        ESP_LOGE(TAG, "failed to get tng_atcacert_signer_cert_size, returned 0x%02x", ret);
        goto exit;
    }
    if (ATCA_SUCCESS != (ret = tng_atcacert_read_signer_cert(cert_buf, cert_len))) {
        ESP_LOGE(TAG, "failed to read tng_atcacert_signer_cert, returned 0x%02x", ret);
        goto exit;
    }
    ECU_DEBUG_LOG(TAG, "atecc_get_tngtls_signer_cert end");
    *err_ret = ret;
    return ESP_OK;

exit:
    *err_ret = ret;
    return ESP_FAIL;
}

esp_err_t atecc_get_tngtls_device_cert(unsigned char *cert_buf, size_t *cert_len, int *err_ret)
{
    int ret;
    ECU_DEBUG_LOG(TAG, "atecc_get_tngtls_signer_cert start");
    if (ATCA_SUCCESS != (ret = tng_atcacert_max_device_cert_size(cert_len))) {
        ESP_LOGE(TAG, "Failed to get tng_atcacert_device_cert_size, returned 0x%02x", ret);
        goto exit;
    }
    if (ATCA_SUCCESS != (ret = tng_atcacert_read_device_cert(cert_buf, cert_len, NULL))) {
        ESP_LOGE(TAG, "failed to read tng_atcacert_device_cert, returned 0x%02x", ret);
        goto exit;
    }
    ECU_DEBUG_LOG(TAG, "atecc_get_tngtls_signer_cert end");

    *err_ret = ret;
    return ESP_OK;

exit:
    *err_ret = ret;
    return ESP_FAIL;
}

