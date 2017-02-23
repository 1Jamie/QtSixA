/*
 * bluetooth.cpp
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
#include <cstdlib>
#include <cerrno>
#include <iostream>
#include <poll.h>
#include <signal.h>
#include <syslog.h>
#include <sys/ioctl.h>

#include <bluetooth/hidp.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/hci_lib.h>

void do_search(int ctl, bdaddr_t *bdaddr, int debug)
{
    syslog(LOG_INFO, "bluetooth.cpp: do_search() starts");

    inquiry_info *info = NULL;
    bdaddr_t src, dst;
    int i, dev_id, num_rsp, length, flags;
    char addr[18];
    uint8_t _class[3];

    ba2str(bdaddr, addr);
    dev_id = hci_devid(addr);
    if (dev_id < 0) {
            dev_id = hci_get_route(NULL);
            hci_devba(dev_id, &src);
    } else
            bacpy(&src, bdaddr);

    length  = 8;    /* ~10 seconds */
    num_rsp = 0;
    flags   = IREQ_CACHE_FLUSH;

    if (debug) syslog(LOG_INFO, "Searching...");

    num_rsp = hci_inquiry(dev_id, length, num_rsp, NULL, &info, flags);

    for (i = 0; i < num_rsp; i++) {
            memcpy(_class, (info+i)->dev_class, 3);
            
            if (debug) syslog(LOG_INFO, "Got device %02X | %02X | %02X", _class[0], _class[1], _class[2]);

            if (_class[1] == 0x25 && (_class[2] == 0x00 || _class[2] == 0x01)) {
                    bacpy(&dst, &(info+i)->bdaddr);
                    ba2str(&dst, addr);

                    if (debug) syslog(LOG_INFO, "Connecting to device %s", addr);
                    do_connect(ctl, &src, &dst, debug);
            }
    }

    bt_free(info);

    if (num_rsp <= 0) {
            if (debug) syslog(LOG_ERR, "No devices in range or visible");
    }
}

void do_connect(int ctl, bdaddr_t *src, bdaddr_t *dst, int debug)
{
    syslog(LOG_INFO, "bluetooth.cpp: do_connect() starts");

    struct hidp_connadd_req req;
    uint16_t uuid = HID_SVCLASS_ID;
    int csk, isk, err;

    memset(&req, 0, sizeof(req));
    err = get_sdp_device_info(src, dst, &req);
    if (err < 0) {
        syslog(LOG_ERR, "Can't get device information");
        return;
    }

    if (uuid == HID_SVCLASS_ID && req.vendor == 0x054c && req.product == 0x0306) {
        csk = l2cap_connect(src, dst, L2CAP_PSM_HIDP_CTRL);
        if (csk < 0) {
                syslog(LOG_ERR, "Can't create HID control channel");
                return;
        }

        isk = l2cap_connect(src, dst, L2CAP_PSM_HIDP_INTR);
        if (isk < 0) {
                syslog(LOG_ERR, "Can't create HID interrupt channel");
                close(csk);
                return;
        }

        if (debug) syslog(LOG_INFO, "Will initiate Remote now");

        dup2(isk, 1);
        close(isk);
        dup2(csk, 0);
        close(csk);

        char bda[18];
        ba2str(dst, bda);

        char cmd[64];
        strcpy(cmd, "/usr/sbin/sixad-remote ");
        strcat(cmd, bda);
        strcat(cmd, " ");
        strcat(cmd, debug ? "1" : "0");

        if (!system(cmd)) {
            syslog(LOG_INFO, "cannot exec '%s'", cmd);
        }

    } else {
        syslog(LOG_ERR, "device ID failed -> %04i, 0x%03X:0x%03X", uuid, req.vendor, req.product);
    }
}

int l2cap_listen(const bdaddr_t *bdaddr, unsigned short psm, int lm, int backlog)
{
    syslog(LOG_ERR, "bluetooth.cpp: l2cap_listen() Starts");

    int sk;
    if ((sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP)) < 0) {
        syslog(LOG_ERR, "bluetooth.cpp: l2cap_listen() Fails to create socket");
        syslog(LOG_ERR, "bluetooth.cpp: error %d (%s)", errno, strerror(errno));
        return -1;
    }

    // 
    struct sockaddr_l2 addr;
    memset(&addr, 0, sizeof(addr));

    addr.l2_family = AF_BLUETOOTH;
    bacpy(&addr.l2_bdaddr, bdaddr);
    addr.l2_psm = htobs(psm);

    if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        syslog(LOG_ERR, "bluetooth.cpp: l2cap_listen() Fails to bind");
        syslog(LOG_ERR, "bluetooth.cpp: error %d (%s)", errno, strerror(errno));
        close(sk);
        return -1;
    }

    setsockopt(sk, SOL_L2CAP, L2CAP_LM, &lm, sizeof(lm));

    //
    struct l2cap_options opts;
    memset(&opts, 0, sizeof(opts));

    opts.imtu = 64;
    opts.omtu = HIDP_DEFAULT_MTU;
    opts.flush_to = 0xffff;

    setsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opts, sizeof(opts));
    if (listen(sk, backlog) < 0) {
        syslog(LOG_ERR, "bluetooth.cpp: l2cap_listen() Fails to listen");
        syslog(LOG_ERR, "bluetooth.cpp: error %d (%s)", errno, strerror(errno));
        close(sk);
        return -1;
    }

    syslog(LOG_ERR, "bluetooth.cpp: l2cap_listen() Finishes");
    return sk;
}

int l2cap_connect(bdaddr_t *src, bdaddr_t *dst, unsigned short psm)
{
    syslog(LOG_INFO, "bluetooth.cpp: l2cap_connect() starts");

    struct sockaddr_l2 addr;
    struct l2cap_options opts;
    int sk;

    if ((sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP)) < 0)
            return -1;

    memset(&addr, 0, sizeof(addr));
    addr.l2_family  = AF_BLUETOOTH;
    bacpy(&addr.l2_bdaddr, src);

    if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
            close(sk);
            return -1;
    }

    memset(&opts, 0, sizeof(opts));
    opts.imtu = HIDP_DEFAULT_MTU;
    opts.omtu = HIDP_DEFAULT_MTU;
    opts.flush_to = 0xffff;

    setsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opts, sizeof(opts));

    memset(&addr, 0, sizeof(addr));
    addr.l2_family  = AF_BLUETOOTH;
    bacpy(&addr.l2_bdaddr, dst);
    addr.l2_psm = htobs(psm);

    if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
            close(sk);
            return -1;
    }

    return sk;
}

void hid_server(int ctl, int csk, int isk, int debug, int legacy)
{
    syslog(LOG_INFO, "bluetooth.cpp: hid_server() Starts");

    // All of the signal blocking functions use a data structure called
    // a signal set to specify what signals are affected.
    sigset_t sigs;

    // Get all current signals to our sigset.
    sigfillset(&sigs);

    // Remove these guys.
    sigdelset(&sigs, SIGCHLD); // Ignore child termination signal.
    sigdelset(&sigs, SIGPIPE); // Clear pipe error signals.
    sigdelset(&sigs, SIGTERM); // Clear terminating signal.
    sigdelset(&sigs, SIGINT);  // Clear interrupting signal.
    sigdelset(&sigs, SIGHUP);  // Clear hang-up signal.

    const int CONTROLLER_COUNT = 2;
    struct pollfd p[2];
    p[0].fd = csk;
    p[1].fd = isk;

    p[0].events = POLLIN | POLLERR | POLLHUP;
    p[1].events = POLLIN | POLLERR | POLLHUP;

    while (!io_canceled()) {
        for (int i=0; i<CONTROLLER_COUNT; i++) {
            p[i].revents = 0;
        }

        struct timespec timeout;
        timeout.tv_sec = 1;
        timeout.tv_nsec = 0;
        if (ppoll(p, CONTROLLER_COUNT, &timeout, &sigs) < 1) {
            continue;
        }

        short events = p[0].revents | p[1].revents;
        if (events & POLLIN) {
            syslog(LOG_INFO, "One event received");

            l2cap_accept(ctl, csk, isk, debug, legacy);

            syslog(LOG_INFO, "One event proccessed");
        }

        if (events & (POLLERR | POLLHUP)) {
            syslog(LOG_ERR, "Server mode loop was broken");
            break;
        }
    }

    syslog(LOG_INFO, "bluetooth.cpp: hid_server() Finishes");
}

// Controller, control socket, info socket ...
bool
l2cap_accept(int ctl, int csk, int isk, int debug, int legacy)
{
    syslog(LOG_INFO, "bluetooth.cpp: l2cap_accept() starts");

    struct sockaddr_l2 addr;
    memset(&addr, 0, sizeof(addr));

    socklen_t addrlen = sizeof(addr);

    // 
    int ctrl_socket;
    if ((ctrl_socket = accept(csk, (struct sockaddr *)&addr, &addrlen)) < 0) {
        syslog(LOG_ERR, "bluetooth.cpp: l2cap_accept() FAILS, unable to accept control stream");
        return false;
    }
    if (getsockname(ctrl_socket, (struct sockaddr *)&addr, &addrlen) < 0) {
        syslog(LOG_ERR, "bluetooth.cpp: l2cap_accept() FAILS, unable to get socket name from control stream");
        return false;
    }
    bdaddr_t addr_src;
    bacpy(&addr_src, &addr.l2_bdaddr);

    // 
    int intr_socket;
    if ((intr_socket = accept(isk, (struct sockaddr *)&addr, &addrlen)) < 0) {
        syslog(LOG_ERR, "bluetooth.cpp: l2cap_accept() FAILS, unable to accept info stream");
        close(ctrl_socket);
        return false;
    }
    bdaddr_t addr_dst;
    bacpy(&addr_dst, &addr.l2_bdaddr);

    // Ensure 
    if (bacmp(&addr_dst, &addr.l2_bdaddr)) {
        syslog(LOG_ERR, "bluetooth.cpp: l2cap_accept() FAILS, intr and ctrl streams from different hosts - rejecting both");
        close(ctrl_socket);
        close(intr_socket);
        return false;
    }


    struct hidp_connadd_req req;
    memset(&req, 0, sizeof(req));

    #ifdef GASIA_GAMEPAD_HACKS
        req.vendor  = 0x054c;
        req.product = 0x0268;
        req.version = 0x0100;
        req.parser  = 0x0100;
        strcpy(req.name, "bluetooth.cpp: l2cap_accept() Gasia Gamepad experimental driver");
    #else
        get_sdp_device_info(&addr_src, &addr_dst, &req);
    #endif

    if (!legacy && req.vendor == 0x054c && req.product == 0x0268) {
        syslog(LOG_INFO, "bluetooth.cpp: l2cap_accept() Will initiate Sixaxis now");

        // New proccess for sixad-sixaxis
        pid_t pid = fork();
        if (pid == 0) {
            dup2(ctrl_socket, 0);
            close(ctrl_socket);
            dup2(intr_socket, 1);
            close(intr_socket);

            char bda[18];
            ba2str(&addr_dst, bda);

            const char* uinput_sixaxis_cmd = "/usr/sbin/sixad-sixaxis";
            const char* debug_mode = debug ? "1" : "0";

            const char* argv[] = { uinput_sixaxis_cmd, bda, debug_mode, NULL };
            char* envp[] = { NULL };

            if (execve(argv[0], (char* const*)argv, envp) < 0) {
                syslog(LOG_INFO, "bluetooth.cpp: l2cap_accept() FAILS, cannot exec %s", uinput_sixaxis_cmd);
                close(1);
                close(0);
                return false;
            }
        }

        return true;
    }

    syslog(LOG_INFO, "bluetooth.cpp: l2cap_accept() Creating new device using the default driver...");
    int err;
    if ((err = create_device(ctl, ctrl_socket, intr_socket)) < 0) {
        syslog(LOG_ERR, "bluetooth.cpp: l2cap_accept() FAILS, HID create error %d (%s)", errno, strerror(errno));
    }

    close(intr_socket);
    close(ctrl_socket);

    return true;
}

/**
 * Create device from controller, control socket and info socket.
 */
int create_device(int ctl, int csk, int isk)
{
    syslog(LOG_INFO, "bluetooth.cpp: create_device() starts");


    struct sockaddr_l2 socketName;
    socklen_t socketNameLength = sizeof(socketName);
    memset(&socketName, 0, socketNameLength);
    if (getsockname(csk, (struct sockaddr *) &socketName, &socketNameLength) < 0) {
        return -1;
    }
    bdaddr_t src;
    bacpy(&src, &socketName.l2_bdaddr);


    struct sockaddr_l2 peerName;
    socklen_t peerNameLength = sizeof(peerName);
    memset(&peerName, 0, peerNameLength);
    if (getpeername(csk, (struct sockaddr *) &peerName, &peerNameLength) < 0) {
        return -1;
    }
    bdaddr_t dst;
    bacpy(&dst, &peerName.l2_bdaddr);


    struct hidp_connadd_req req;
    memset(&req, 0, sizeof(req));
    req.ctrl_sock = csk;
    req.intr_sock = isk;
    req.flags     = 0;
    req.idle_to   = 1800;

    #ifdef GASIA_GAMEPAD_HACKS
        req.vendor  = 0x054c;
        req.product = 0x0268;
        req.version = 0x0100;
        req.parser  = 0x0100;
        strcpy(req.name, "Gasia Gamepad experimental driver");
    #else
        int err = get_sdp_device_info(&src, &dst, &req);
        if (err < 0) {
            return err;
        }        
    #endif

    char bda[18];
    ba2str(&dst, bda);
    syslog(LOG_INFO, "Connected %s (%s)", req.name, bda);
    if (req.vendor == 0x054c && req.product == 0x0268) {
        enable_sixaxis(csk);
    }

    ioctl(ctl, HIDPCONNADD, &req);
    return 0;
}

// Session Description Protocol / Service Discovery Protocol.
int get_sdp_device_info(const bdaddr_t *src, const bdaddr_t *dst,
                        /* INOUT */ struct hidp_connadd_req *aConnectionRequest)
{
    syslog(LOG_INFO, "bluetooth.cpp: get_sdp_device_info() starts");

    // Determine session.
    sdp_session_t *sdpSession =
        sdp_connect(src, dst, SDP_RETRY_IF_BUSY | SDP_WAIT_ON_CLOSE);
    if (!sdpSession) {
        syslog(LOG_ERR, "unable to connect to sdp session");
        return -1;
    }

    // Determine Plug 'n Play class info.
    // ... returns Vendor, Product, Version info
    uuid_t pnpSVClass;
    sdp_uuid16_create(&pnpSVClass, PNP_INFO_SVCLASS_ID);
    sdp_list_t *search = sdp_list_append(NULL, &pnpSVClass);

    uint32_t range = 0x0000ffff;
    sdp_list_t *attrid = sdp_list_append(NULL, &range);

    sdp_list_t *pnpResponseList;
    if (sdp_service_search_attr_req(sdpSession,
        search, SDP_ATTR_REQ_RANGE, attrid, &pnpResponseList) && pnpResponseList) {

        // Found the PNP responseList, now parse it.
        sdp_record_t *pnpResponseData = (sdp_record_t *) pnpResponseList->data;

        sdp_data_t *vendorData = sdp_data_get(pnpResponseData, 0x0201);
        aConnectionRequest->vendor = vendorData ? vendorData->val.uint16 : 0x0000;

        sdp_data_t *productData = sdp_data_get(pnpResponseData, 0x0202);
        aConnectionRequest->product = productData ? productData->val.uint16 : 0x0000;

        sdp_data_t *versionData = sdp_data_get(pnpResponseData, 0x0203);
        aConnectionRequest->version = versionData ? versionData->val.uint16 : 0x0000;

        sdp_record_free(pnpResponseData);
    }

    sdp_list_free(search, NULL);
    sdp_list_free(attrid, NULL);

    // Determine Human Interface Device class info.
    uuid_t hidSVClass;
    sdp_uuid16_create(&hidSVClass, HID_SVCLASS_ID);
    search = sdp_list_append(NULL, &hidSVClass);
    attrid = sdp_list_append(NULL, &range);

    sdp_list_t *hid_rsp;
    if (!sdp_service_search_attr_req(sdpSession, search, SDP_ATTR_REQ_RANGE, attrid, &hid_rsp) || !hid_rsp) {
        syslog(LOG_ERR, "unable to get HID device information");
        return -1;
    }

    sdp_record_t *pnpResponseData = (sdp_record_t *) hid_rsp->data;

    sdp_data_t *pdlist = sdp_data_get(pnpResponseData, 0x0101);
    if (pdlist) {
        sdp_data_t *pdlist2 = sdp_data_get(pnpResponseData, 0x0102);
        if (pdlist2) {
            if (strncmp(pdlist->val.str, pdlist2->val.str, 5)) {
                strncpy(aConnectionRequest->name, pdlist2->val.str, sizeof(aConnectionRequest->name) - 1);
                strcat(aConnectionRequest->name, " ");
            }
            strncat(aConnectionRequest->name, pdlist->val.str,
                    sizeof(aConnectionRequest->name) - strlen(aConnectionRequest->name));

        } else {
            strncpy(aConnectionRequest->name, pdlist->val.str, sizeof(aConnectionRequest->name) - 1);
        }

    } else {
        sdp_data_t *pdlist3 = sdp_data_get(pnpResponseData, 0x0100);
        if (pdlist3) {
            strncpy(aConnectionRequest->name, pdlist3->val.str, sizeof(aConnectionRequest->name) - 1);
        }
    }

    sdp_data_t *parserData = sdp_data_get(pnpResponseData, 0x0201);
    aConnectionRequest->parser = parserData ? parserData->val.uint16 : 0x0100;

    sdp_data_t *subclassData = sdp_data_get(pnpResponseData, 0x0202);
    aConnectionRequest->subclass = subclassData ? subclassData->val.uint8 : 0;

    sdp_data_t *countryData = sdp_data_get(pnpResponseData, 0x0203);
    aConnectionRequest->country = countryData ? countryData->val.uint8 : 0;

    // If some thing is true, then reverse some things ...
    // What is code x206 referring to?
    sdp_data_t *pdlistFOO = sdp_data_get(pnpResponseData, 0x0206);
    if (pdlistFOO) {
            pdlistFOO = pdlistFOO->val.dataseq; // interesting
            pdlistFOO = pdlistFOO->val.dataseq; // VERIFY ME !!!
            pdlistFOO = pdlistFOO->next;

            aConnectionRequest->rd_data = (uint8_t*)malloc(pdlistFOO->unitSize);
            if (aConnectionRequest->rd_data) {
                    memcpy(aConnectionRequest->rd_data, (unsigned char *) pdlistFOO->val.str, pdlistFOO->unitSize);
                    aConnectionRequest->rd_size = pdlistFOO->unitSize;
                    epox_endian_quirk(aConnectionRequest->rd_data, aConnectionRequest->rd_size);
            }
    }

    // Cleanup and return
    sdp_record_free(pnpResponseData);

    sdp_list_free(search, NULL);
    sdp_list_free(attrid, NULL);

    sdp_close(sdpSession);

    return 0;
}

/**
 * USAGE_PAGE (Keyboard)    05 07
 * USAGE_MINIMUM (0)        19 00
 * USAGE_MAXIMUM (65280)    2A 00 FF   <= must be FF 00
 * LOGICAL_MINIMUM (0)      15 00
 * LOGICAL_MAXIMUM (65280)  26 00 FF   <= must be FF 00
 */
void epox_endian_quirk(/* INOUT */ unsigned char *data, int size)
{
    if (!data) {
        return;
    }

    syslog(LOG_INFO, "bluetooth.cpp: epox_endian_quirk() Starts");
    unsigned char pattern[] =
        { 0x05, 0x07,
          0x19, 0x00,
          0x2a, 0x00, 0xff,
          0x15, 0x00,
          0x26, 0x00, 0xff };

    for (unsigned int i = 0; i < size - sizeof(pattern); i++) {
        if (!memcmp(data + i, pattern, sizeof(pattern))) {
                data[i + 5] = 0xff;
                data[i + 6] = 0x00;
                data[i + 10] = 0xff;
                data[i + 11] = 0x00;
        }
    }

    syslog(LOG_INFO, "bluetooth.cpp: epox_endian_quirk() Finishes");
}
