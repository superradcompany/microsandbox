/*
 * vmnet_shim.c — C wrapper around vmnet.framework's block-based APIs.
 *
 * vmnet uses Objective-C blocks for callbacks, which are not directly
 * callable from Rust. This shim converts them to function-pointer + context
 * style callbacks and provides synchronous wrappers where appropriate.
 */

#include <vmnet/vmnet.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* Result struct for vmnet_start_interface. */
struct vmnet_start_result {
    vmnet_return_t status;
    /* Extracted from interface_param dictionary. */
    char mac_address[18];    /* "aa:bb:cc:dd:ee:ff\0" */
    uint64_t mtu;
    uint64_t max_packet_size;
    char start_address[64];  /* gateway/start IPv4 */
    char end_address[64];    /* DHCP end IPv4 */
    char subnet_mask[64];    /* subnet mask */
    char nat66_prefix[64];   /* IPv6 ULA prefix (e.g. "fd9b:5a14:ba57:e3d3::") */
};

/*
 * Synchronously start a vmnet interface in shared mode.
 *
 * Blocks until the completion handler fires. Returns the interface_ref
 * through *out_iface (NULL on failure) and populates *out_result with
 * the resolved parameters.
 */
void
vmnet_shim_start_shared(interface_ref *out_iface,
                        struct vmnet_start_result *out_result)
{
    dispatch_queue_t queue = dispatch_queue_create("dev.microsandbox.vmnet",
                                                   DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    xpc_object_t desc = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(desc, vmnet_operation_mode_key, VMNET_SHARED_MODE);

    __block struct vmnet_start_result result;
    memset(&result, 0, sizeof(result));

    interface_ref iface = vmnet_start_interface(desc, queue,
        ^(vmnet_return_t status, xpc_object_t interface_param) {
            result.status = status;
            if (status == VMNET_SUCCESS && interface_param != NULL) {
                const char *mac = xpc_dictionary_get_string(interface_param,
                                                            vmnet_mac_address_key);
                if (mac) {
                    strncpy(result.mac_address, mac, sizeof(result.mac_address) - 1);
                }
                result.mtu = xpc_dictionary_get_uint64(interface_param,
                                                       vmnet_mtu_key);
                result.max_packet_size = xpc_dictionary_get_uint64(interface_param,
                                                                    vmnet_max_packet_size_key);
                const char *start = xpc_dictionary_get_string(interface_param,
                                                               vmnet_start_address_key);
                if (start) {
                    strncpy(result.start_address, start, sizeof(result.start_address) - 1);
                }
                const char *end = xpc_dictionary_get_string(interface_param,
                                                             vmnet_end_address_key);
                if (end) {
                    strncpy(result.end_address, end, sizeof(result.end_address) - 1);
                }
                const char *mask = xpc_dictionary_get_string(interface_param,
                                                              vmnet_subnet_mask_key);
                if (mask) {
                    strncpy(result.subnet_mask, mask, sizeof(result.subnet_mask) - 1);
                }
                const char *nat66 = xpc_dictionary_get_string(interface_param,
                                                               vmnet_nat66_prefix_key);
                if (nat66) {
                    strncpy(result.nat66_prefix, nat66, sizeof(result.nat66_prefix) - 1);
                }
            }
            dispatch_semaphore_signal(sem);
        });

    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

    xpc_release(desc);
    dispatch_release(sem);
    dispatch_release(queue);

    *out_iface = iface;
    *out_result = result;
}

/*
 * Synchronously stop a vmnet interface.
 */
vmnet_return_t
vmnet_shim_stop(interface_ref iface)
{
    dispatch_queue_t queue = dispatch_queue_create("dev.microsandbox.vmnet.stop",
                                                   DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    __block vmnet_return_t stop_status = VMNET_FAILURE;

    vmnet_return_t ret = vmnet_stop_interface(iface, queue,
        ^(vmnet_return_t status) {
            stop_status = status;
            dispatch_semaphore_signal(sem);
        });

    if (ret == VMNET_SUCCESS) {
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    }

    dispatch_release(sem);
    dispatch_release(queue);

    return (ret == VMNET_SUCCESS) ? stop_status : ret;
}

/*
 * Set up a packet-available event callback that writes a byte to a pipe FD.
 *
 * This converts the block-based event callback into a file-descriptor
 * notification that can be polled with tokio's AsyncFd.
 */
vmnet_return_t
vmnet_shim_set_event_fd(interface_ref iface, int notify_fd)
{
    dispatch_queue_t queue = dispatch_queue_create("dev.microsandbox.vmnet.event",
                                                   DISPATCH_QUEUE_SERIAL);

    vmnet_return_t ret = vmnet_interface_set_event_callback(iface,
        VMNET_INTERFACE_PACKETS_AVAILABLE, queue,
        ^(interface_event_t event_mask, xpc_object_t event) {
            (void)event_mask;
            (void)event;
            char byte = 1;
            ssize_t wr = write(notify_fd, &byte, 1);
            if (wr == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
                (void)wr;
            }
        });

    /* The framework retains the queue for the callback's lifetime.
     * Release our creation reference to avoid a leak. */
    dispatch_release(queue);

    return ret;
}
