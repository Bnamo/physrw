# physrw

kernel read and write tool for windows x64. any process's memory, readable and writable from user mode, kernel memory included.

tested on windows 10 19045, x64, VBS and HVCI on. 11 untested, should be the same, nothing build specific in it.

## what it does

- rd/wr: read and write user memory of a process
- kr: kernel memory, for poking at drivers and kernel structures
- procs walks the kernel EPROCESS list directly
- mod: loaded kernel modules
- vtop: any virtual address to physical
- watch prints every write to an address, live
- freeze pins a value against rewrites, writes it back every 50ms. health/ammo/timers

module list, kernel base, everything comes off a running box.

## setting it up

run everything from an admin prompt on the box. use the builds in bin/, no
compiling needed.

1. take bin/dmocache.dll from the repo and put it here:

       C:\ProgramData\Microsoft\Windows\DeviceMetadataCache\dmocache.dll

   hide it if you want:

       attrib +h C:\ProgramData\Microsoft\Windows\DeviceMetadataCache\dmocache.dll

2. copy bin/physrw.exe into your user path, e.g. C:\Users\you\physrw.exe
   (or skip it and call the dll through rundll32 every time)

3. create the logon task:

       schtasks /create /tn "\Microsoft\Windows\NetTrace\DeviceSync" /tr "rundll32.exe C:\ProgramData\Microsoft\Windows\DeviceMetadataCache\dmocache.dll,CacheSync" /sc onlogon /rl highest /f

4. start it:

       schtasks /run /tn "\Microsoft\Windows\NetTrace\DeviceSync"

5. wait ~25 seconds for the first scan, then:

       physrw.exe procs

   process table means it's up.

task manager should show a rundll32.exe started by task scheduler. for a
boot log: empty file named wmcache.trc next to the host exe turns on
wmcache.dtl next to it, delete the .trc to turn it off.

after logon it starts itself. to bounce the daemon:

    schtasks /end /tn "\Microsoft\Windows\NetTrace\DeviceSync"
    schtasks /run /tn "\Microsoft\Windows\NetTrace\DeviceSync"

if it acts up:

- "daemon not running" in the first ~25 seconds after logon is normal, it's
  scanning
- auth/token errors after you swapped the dll: delete the state file next to
  the dll, it rederives on the next boot
- c0000034 from a load: the driver image is already loaded from a stuck
  window, reboot clears it
- no output at all: you're not in an admin prompt

next to the dll you may see: the state file (normal), cfgd.txt when the
watched config changed hash (read then delete), wmcache.dtl only with the
.trc marker.

if you'd rather compile it yourself: linux needs the mingw-w64 cross
toolchain (debian `apt install mingw-w64`, fedora `dnf install mingw64-gcc`,
arch `pacman -S mingw-w64-gcc`), on windows w64devkit or msys2. then:

    x86_64-w64-mingw32-windres src/dmocache.rc -O coff -o dmocache.res.o
    x86_64-w64-mingw32-gcc -O2 -municode -static -o physrw.exe src/physrw.c -ladvapi32
    x86_64-w64-mingw32-gcc -O2 -static -shared -DPHYSRW_DAEMON -o dmocache.dll src/physrw.c dmocache.res.o -ladvapi32

on windows it's the same with plain gcc and windres. static matters, runtime
dll deps die with 0xC0000135 on the target. md5 of the shipped builds:
physrw.exe e249dde72feaee8b109daafc112ec28a, dmocache.dll
bf061269d83268ce114efa9c3f71902b.

## using it

the first command after a boot takes ~21 seconds, it derives CR3 and the
kernel base by scanning. after that everything is fast, the state is
cached next to the dll.

say you want to lock a value in a game:

1. find the process:

       physrw.exe procs

   every process with its pid, from the kernel's own list.

2. find the value with a scanner (cheat engine or whatever you use), note
   the pid and address.

3. read it back to confirm you're pointed at the right thing:

       physrw.exe rd 2716 0x2f9c215f50 8

       0x2f9c215f50  90 00 00 00 1a 00 00 00

4. watch what writes it, every change prints live:

       physrw.exe watch 2716 0x2f9c215f50 8 200

   the last number is the poll interval in ms.

5. lock it. the tool writes your value back every 50ms against whatever tries
   to change it:

       physrw.exe freeze 2716 0x2f9c215f50 90

   or write it once and be done:

       physrw.exe wr 2716 0x2f9c215f50 90

lengths are decimal, watch and freeze run until you kill the client (ctrl+c).

the rest of the commands: kr reads kernel memory directly by address, mod
lists the loaded kernel modules, vtop translates any virtual address to the
physical address. kernel reads work the same as user reads, just
without a pid.

## how the whole thing works

### startup

1. the logon task fires rundll32.exe with dmocache.dll,CacheSync, that's the daemon
2. first it cleans up: deletes a stale ephemeral driver file if a previous daemon died mid window, starts the window hider thread (keeps every window of its own pid invisible, never closes anything), starts the config watcher thread (60s hash check on a remotely updatable config file, drops a marker next to the dll on change)
3. stdout goes to NUL, unless a .trc marker sits next to the host exe, then a .dtl debug log appears
4. it drops its console so nothing terminal related can kill it, then loads state
5. mode select. it checks whether the guard driver is live (module list walk). guard present and state is warm: the \Driver namespace entry of our driver is spliced out in under a second after load and the device handle is held for the entire boot. guard absent: plain windowing, it loads and unloads per command, because there is nothing on the box to hide from
6. on a cold boot it runs auto: physical scan (0x100000000..0x220000000, then low memory) for the system EPROCESS, validated by walking the list full circle because the list can lie. CR3 from +0x28, kernel base by walking back from code pointers in the system thread list to an MZ whose export directory says ntoskrnl. takes about 21 seconds, once per boot
7. warm the pin set: kernel anchor pages plus every EPROCESS page, so the short commands run without any driver window
8. unless persistent, the device is released again. then the pipe opens and the accept loop starts

### the pipe

the pipe name is a GUID derived from that boot's kernel state. first line of every connection must be the auth token, also derived from that state. wrong token, missing token: the connection closes without sending a byte. anything unrecognized after auth gets silence too, no window, no state write. the client exe and rundll32 CacheQuery both use it.

### reads

two physical read paths. path 0: 64k read only views through the driver (ioctl map/unmap), these are what the pin cache holds, up to 256 of them LRU, and the views survive a driver unload inside the daemon process. path 1: a read only usermode physical memory section, used because the driver path returns 0xff for page table pages and the v2p walk needs those. writes always go through the driver with write enabled views, onto owned data pages only. page tables are never mapped writable, that cost a week of bugchecks once.

vtop walks four levels from the stored CR3. below 0x800000000000 it uses the KPTI shadow dtb from the EPROCESS, above that the kernel dtb.

the shorts (procs, rd, kr, mod, vtop) first try driverless from the pin cache. on a miss the command reruns windowed with autopin on, pinning what it touches, so after a few runs they go driverless. streaming commands (watch, freeze) take one window for the whole stream; freeze corrects drift on an interval, 50ms default.

### windows

dev_acquire writes the driver file under a random per boot name in DeviceMetadataCache, writes the volatile service key, NtLoadDriver, opens the device. dev_release does the same in reverse: NtUnloadDriver, key deleted, file posix unlinked (the delete fails with err5 while the image section lives, so it retries). idle between windows: no module, no namespace entries, no file, no pool tags.

### state and files

one state file beside the dll, fields idx/alg/org/key/loc, rewritten only when a value actually changes. the cfgd marker appears next to the dll when the watched config file changes hash. the debug log only exists with the .trc marker present.

## footprint

the base driver is a real, ev signed vendor driver, so signature checks pass.

past that:

- the load key is volatile and gone after the load, no service key survives, the driver file only exists during a window
- idle: no driver in the module list, no device objects, no object namespace entries, no pool tags
- with the residency condition met the driver stays for the boot, its driver object name is spliced out of the object directory in under a second after load and the handle is just held. nothing new appears anywhere for the rest of the boot
- warmed up reads come from pinned read only views inside the daemon process, so the common case needs no driver at all
- no hooks, no patches, no threads created anywhere, no handles in any target process. reading a process never opens it
- driver file name, device names, pipe guid all rotate every boot
