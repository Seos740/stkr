This is a minimal PS/2 keyboard driver in user-space for a Mach-like microkernel.

Files:
- kbd.defs: Defines the Mach IPC interface.
- kbd_server.c: Implements a device server that reads scan codes from the PS/2 port.

Instructions:
1. Use 'mig' to generate the header and user/server stubs:
   mig kbd.defs

2. Compile:
   gcc -o kbd_server kbd_server.c kbdUser.c -lmach -lIOKit

3. Run with root privileges (for access to I/O ports):
   sudo ./kbd_server

This example polls the PS/2 keyboard port and returns scan codes over IPC.