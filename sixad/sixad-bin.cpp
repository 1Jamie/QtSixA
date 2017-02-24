/*
 * sixad-bin.cpp
 *
 * This file is part of the QtSixA, the Sixaxis Joystick Manager
 * Copyright 2008-10 Filipe Coelho <falktx@gmail.com>
 *
 * QtSixA can be redistributed and/or modified under the terms of the GNU General
 * Public License (Version 2), as published by the Free Software Foundation.
 * A copy of the license is included in the QtSixA source code, or can be found
 * online at www.gnu.org/licenses.
 *
 * QtSixA is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 */

#include "bluetooth.h"
#include "shared.h"

#include <unistd.h>
#include <iostream>
#include <signal.h>
#include <stdlib.h>
#include <syslog.h>

#include <sys/ioctl.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define MAX_DEVICES_PER_HCI_CONTROLLER 4

/* Reset device on Host Controller Interface (HCI) */
static void cmd_reset(int aHCIController, int aDevice)
{
    ioctl(aHCIController, HCIDEVUP, aDevice);
    ioctl(aHCIController, HCIDEVDOWN, aDevice);
}


// Dummy handler definition
static void dummySignHupHandler(int sig) {
    // Do nothing.
}


/**
 * Bluetooth Address/Protocol family, raw protocol interface,
 * Host Controller Interface of local devices.
 */
static void resetAllBluetooth() {
    syslog(LOG_ERR, "sixad-bin.cpp: resetAllBluetooth() Enabling ALL Bluetooth ... Starts");

    int hciController;

    // Open a Bluetooth raw socket talking HCI protocol
    if ((hciController = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) >= 0) {
        syslog(LOG_ERR, "sixad-bin.cpp: HCI Controller Found !");
        syslog(LOG_ERR, "sixad-bin.cpp:    Scanning %d reported devices ...",
            MAX_DEVICES_PER_HCI_CONTROLLER);

        for (int i = 0; i < MAX_DEVICES_PER_HCI_CONTROLLER; i++) {
            struct hci_dev_info hciDeviceInfo;
            hciDeviceInfo.dev_id = i;

            if (ioctl(hciController, HCIGETDEVINFO, (void *) &hciDeviceInfo) == 0) {
                if (!hci_test_bit(HCI_RAW, &hciDeviceInfo.flags)) {
                    syslog(LOG_ERR, "sixad-bin.cpp:       HCI Device #%d [%.8s] Not RAW !",
                        i, hciDeviceInfo.name);
                } else if (bacmp(&hciDeviceInfo.bdaddr, BDADDR_ANY)) {
                    syslog(LOG_ERR, "sixad-bin.cpp:       HCI Device #%d [%.8s] Not BDADDR_ANY !",
                        i, hciDeviceInfo.name);
                } else {
                    // Open it, read 100 bytes, then close. (Ummmm, why???)
                    syslog(LOG_ERR, "sixad-bin.cpp:       HCI Device #%d [%.8s] Reset !",
                        i, hciDeviceInfo.name);

                    int dd = hci_open_dev(hciDeviceInfo.dev_id);
                    hci_read_bd_addr(dd, &hciDeviceInfo.bdaddr, 1000);
                    hci_close_dev(dd);
                }

            } else {
                syslog(LOG_ERR, "sixad-bin.cpp:       HCI Device #%d : Not found", i);
            }

            syslog(LOG_ERR, "sixad-bin.cpp:       Device #%d : Reset", i);
            cmd_reset(hciController, hciDeviceInfo.dev_id);
        }

    } else {
        syslog(LOG_ERR, "sixad-bin.cpp: No HCI Controller found (?)");
    }

    syslog(LOG_ERR, "sixad-bin.cpp: resetAllBluetooth() Enabling ALL Bluetooth ... Finishes");
}

/**
 * Main routine !
 */
int
main(int argc, char *argv[]) {
    open_log("sixad-bin");
    syslog(LOG_INFO, "sixad-bin.cpp: Starts !");

    // Default values and overrides.
    int debug = true, legacy = false, remote = false;
    if (argc > 3) {
        debug = atoi(argv[1]);
        legacy = atoi(argv[2]);
        remote = atoi(argv[3]);
    }

    // Testing code ... "Enable all bluetooth adapters"
    resetAllBluetooth();

    // Open a Bluetooth raw socket talking HIDP protocol
    int btHIDSocket = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HIDP);
    if (btHIDSocket < 0) {
        syslog(LOG_ERR, "sixad-bin.cpp: Can't open HIDP control socket");
        close(btHIDSocket);
        return 1;
    }

    // BD Remote only
    if (remote) {
        syslog(LOG_INFO, "sixad-bin.cpp: BD Remote mode active, hold Enter+Start on your remote now");

        bdaddr_t addrRemote;
        bacpy(&addrRemote, BDADDR_ANY);

        while (!io_canceled()) {
            do_search(btHIDSocket, &addrRemote, debug);
            sleep(2);
        }

        close(btHIDSocket);
        syslog(LOG_INFO, "sixad-bin.cpp: Done, BD Remote");
        return 0;
    }


    // Determine the control socket
    bdaddr_t addrSocket;
    bacpy(&addrSocket, BDADDR_ANY);
    int csk = l2cap_listen(&addrSocket, L2CAP_PSM_HIDP_CTRL, L2CAP_LM_MASTER, 10);
    if (csk < 0) {
        syslog(LOG_ERR, "sixad-bin.cpp: %s: ERROR: %d, Can't listen on HID control channel", argv[0], csk);
        close(csk);
        close(btHIDSocket);
        return 1;
    }

    // Determine the info socket
    int isk = l2cap_listen(&addrSocket, L2CAP_PSM_HIDP_INTR, L2CAP_LM_MASTER, 10);
    if (isk < 0) {
        syslog(LOG_ERR, "sixad-bin.cpp: Can't listen on HID interrupt channel");
        close(isk);
        close(csk);
        close(btHIDSocket);
        return 1;
    }

    // 
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_NOCLDSTOP;
    sa.sa_handler = sig_term;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sa.sa_handler = dummySignHupHandler;
    sigaction(SIGHUP, &sa, NULL);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGCHLD, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);

    // Here we go ! Start polling, and whatever.
    syslog(LOG_INFO, "sixad-bin.cpp: Started, press the PS button now");

    // Controller, control socket, info socket ...
    hid_server(btHIDSocket, csk, isk, debug, legacy);

    // All done !
    close(isk);
    close(csk);
    close(btHIDSocket);

    syslog(LOG_INFO, "sixad-bin.cpp: Done");
    return 0;
}
