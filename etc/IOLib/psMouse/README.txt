This is a minimal PS/2 mouse driver in user-space for a Mach-like microkernel.

Files:
- mouse.defs: Defines the Mach IPC interface for mouse input.
- mouse_server.c: Implements a device server that reads 3-byte mouse packets from the PS/2 port.

Instructions:
1. Use 'mig' to generate the header and stubs:
   mig mouse.defs

2. Compile:
   gcc -o mouse_server mouse_server.c mouseUser.c -lmach -lIOKit

3. Run with root privileges (for access to I/O ports):
   sudo ./mouse_server

This driver polls the PS/2 mouse port and returns the 3-byte packet (button, dx, dy).