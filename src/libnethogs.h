#ifndef LIBNETHOGS_H_
#define LIBNETHOGS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#define NETHOGS_DSO_VISIBLE __attribute__((visibility("default")))
#define NETHOGS_DSO_HIDDEN __attribute__((visibility("hidden")))

#define NETHOGS_APP_ACTION_SET 1
#define NETHOGS_APP_ACTION_REMOVE 2

#define NETHOGS_STATUS_OK 0
#define NETHOGS_STATUS_FAILURE 1
#define NETHOGS_STATUS_NO_DEVICE 2

typedef struct NethogsMonitorRecord {
  int record_id;
  const char *name;
  int pid;
  uint32_t uid;
  const char *device_name;
  uint32_t sent_bytes;
  uint32_t recv_bytes;
  float sent_kbs;
  float recv_kbs;
} NethogsMonitorRecord;

/**
 * @brief Defines a callback to handle updates about applications
 * @param action NETHOGS_APP_ACTION_SET if data is being added or updated,
 *        NETHOGS_APP_ACTION_REMOVE if data is being removed.
 *        the record_id member is used to uniquely identify the data being
 * update or removed.
 * @param data a pointer to an application usage data. the pointer remains valid
 * until
 *        the callback is called with NETHOGS_APP_ACTION_REMOVE for the same
 * pointer.
 *        the user should not modify the content of the structure pointed by
 * data.
 */
typedef void (*NethogsMonitorCallback)(int action,
                                       NethogsMonitorRecord const *data);

/**
 * @brief Enter the process monitoring loop and reports updates using the
 * callback provided as parameter.
 * This call will block until nethogsmonitor_breakloop() is called or a failure
 * occurs.
 * @param cb A pointer to a callback function following the
 * NethogsMonitorCallback definition
 */

NETHOGS_DSO_VISIBLE int nethogsmonitor_loop(NethogsMonitorCallback cb);

/**
 * @brief Makes the call to nethogsmonitor_loop return.
 */
NETHOGS_DSO_VISIBLE void nethogsmonitor_breakloop();

#undef NETHOGS_DSO_VISIBLE
#undef NETHOGS_DSO_HIDDEN

#ifdef __cplusplus
}
#endif

#endif // LIBNETHOGS_H_
