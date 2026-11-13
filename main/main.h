#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include "esp_now.h"


// hardware macros
#define HIGH                1
#define LOW                 0

// hardware definition macros
#define LED_PIN             21

#define ESPNOW_QUEUE_SIZE   6
#define MESSAGE_LENGTH      32

#define IS_BROADCAST_ADDR(addr) (memcmp(addr, s_broadcast_mac, ESP_NOW_ETH_ALEN) == 0)

typedef enum {
    ESPNOW_SEND_CB_EVT,
    ESPNOW_RECV_CB_EVT,
} espnow_event_id_t;

typedef struct {
    uint8_t mac_addr[ESP_NOW_ETH_ALEN];
    esp_now_send_status_t status;
} espnow_event_send_cb_t;

typedef struct {
    uint8_t mac_addr[ESP_NOW_ETH_ALEN];
    uint8_t *data;
    int data_len;
} espnow_event_recv_cb_t;

typedef union {
    espnow_event_send_cb_t send_cb;
    espnow_event_recv_cb_t recv_cb;
} espnow_event_info_t;

/* When ESPNOW sending or receiving callback function is called, post event to ESPNOW task. */
typedef struct {
    espnow_event_id_t id;
    espnow_event_info_t info;
} espnow_event_t;

/* data struct */
typedef struct {
    uint8_t send_peer[ESP_NOW_ETH_ALEN];
    int count;
    char msg[MESSAGE_LENGTH];
} espnow_data_t;

typedef enum {
    DISCOVERY,
    AUTHENTICATION,
    SESSION_OK,
} session_state_t;

enum {
    ESPNOW_DATA_BROADCAST,
    ESPNOW_DATA_UNICAST,
    ESPNOW_DATA_MAX,
};

#endif /* MAIN_H */