#include "mouse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <device/device_types.h>
#include <mach/message.h>
#include <mach/mach_host.h>
#include <mach/port.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/io.h>

#define MOUSE_DATA_PORT 0x60
#define MOUSE_STATUS_PORT 0x64

kern_return_t mouse_read(mach_port_t client, char **data, mach_msg_type_number_t *count) {
    static char buffer[3];

    // Wait for data
    if (!(inb(MOUSE_STATUS_PORT) & 0x01)) {
        buffer[0] = buffer[1] = buffer[2] = 0;
        *data = buffer;
        *count = 3;
        return KERN_SUCCESS;
    }

    // Read 3-byte packet from PS/2 mouse
    buffer[0] = inb(MOUSE_DATA_PORT);
    while (!(inb(MOUSE_STATUS_PORT) & 0x01));
    buffer[1] = inb(MOUSE_DATA_PORT);
    while (!(inb(MOUSE_STATUS_PORT) & 0x01));
    buffer[2] = inb(MOUSE_DATA_PORT);

    *data = buffer;
    *count = 3;
    return KERN_SUCCESS;
}

int main() {
    mach_port_t bootstrap_port;
    task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap_port);

    mach_port_t server_port;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &server_port);
    mach_port_insert_right(mach_task_self(), server_port, server_port, MACH_MSG_TYPE_MAKE_SEND);

    printf("[mouse_server] Server port created. Listening for requests...\n");

    if (ioperm(MOUSE_DATA_PORT, 1, 1) || ioperm(MOUSE_STATUS_PORT, 1, 1)) {
        perror("ioperm");
        return 1;
    }

    mach_msg_server(mouse_server, 2048, server_port, 0);
    return 0;
}