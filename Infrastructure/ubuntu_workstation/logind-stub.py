#!/usr/bin/env python3
"""Minimal org.freedesktop.login1 stub for the containerized XFCE desktop.

xfce4-panel's clock plugin (libclock) connects to the D-Bus system bus and
looks for org.freedesktop.login1 so it can subscribe to PrepareForSleep
signals and correct the displayed time after a system wake-up. In a Docker
container there is no systemd-logind, so the probe fails and produces:

    libclock-Message: logind not active
    libclock-WARNING: could not instantiate a sleep monitor

This stub registers the bus name and a no-op Manager object. libclock's
probe succeeds, the warnings disappear, and the sleep signal is never
emitted (the container never sleeps, so none of this matters functionally).
"""
import sys
import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib


class LogindManager(dbus.service.Object):
    @dbus.service.signal("org.freedesktop.login1.Manager", signature="b")
    def PrepareForSleep(self, start):
        pass  # never emitted — the container never sleeps


def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    try:
        bus = dbus.SystemBus()
        bus_name = dbus.service.BusName("org.freedesktop.login1", bus)
        manager = LogindManager(bus, "/org/freedesktop/login1")
    except dbus.DBusException as exc:
        print(f"[logind-stub] could not register on system bus: {exc}",
              file=sys.stderr)
        sys.exit(1)
    loop = GLib.MainLoop()
    loop.run()


if __name__ == "__main__":
    main()
