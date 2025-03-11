//device.c: usb functions using libusb
//Copyright 2006 Jeroen Domburg <s1fwx@jeroen.ietsmet.nl>
//This software is licensed under the GNU GPL.

#define	VENDOR_ID	4310
#define	PRODUCT_ID	65361

#include "device.h"
#include "debug.h"

USB_HANDLE device_open() {
    USB_HANDLE device_handle = NULL;
    libusb_device** devs;
    ssize_t cnt;
    int r;

    libusb_init(NULL);

    cnt = libusb_get_device_list(NULL, &devs);
    if (cnt < 0) {
        libusb_exit(NULL);
        fprintf(stderr, "libusb_get_device_list(): no devices? (libusb error '%s')\n", libusb_error_name(r));
        return NULL;
    }

    libusb_device* dev;
    int i = 0, j = 0;
    uint8_t path[8];

    while ((dev = devs[i++]) != NULL) {
        struct libusb_device_descriptor desc;
        r = libusb_get_device_descriptor(dev, &desc);
        if (r < 0) {
            fprintf(stderr, "libusb_get_device_descriptor(): failed to get device descriptor (libusb error '%s')\n", libusb_error_name(r));
            return NULL;
        }

        printf("%04x:%04x (bus %d, device %d)",
            desc.idVendor, desc.idProduct,
            libusb_get_bus_number(dev), libusb_get_device_address(dev));

        r = libusb_get_port_numbers(dev, path, sizeof(path));
        if (r > 0) {
            printf(" path: %d", path[0]);
            for (j = 1; j < r; j++)
                printf(".%d", path[j]);
        }

        if (desc.idProduct == PRODUCT_ID && desc.idVendor == VENDOR_ID) {
            printf(" BINGO!\n");
            r = libusb_open(dev, &device_handle);
            if (r < 0 || device_handle == NULL) {
                fprintf(stderr, "libusb_open(): open  (libusb error '%s')\n", libusb_error_name(r));
                libusb_free_device_list(devs, 1);

                libusb_exit(NULL);
                return NULL;
            }

            libusb_claim_interface(device_handle, 0);

            libusb_free_device_list(devs, 1);

            break;
        }
        printf("\n");
    }

    return device_handle;
}


// -----------------------------------------------------------------------------------------------
bool device_close(USB_HANDLE hd)
{
    libusb_close(hd);
    return TRUE;
}


// -----------------------------------------------------------------------------------------------
long device_send(USB_HANDLE hd, void* data, uint32 max_data)
{
    int transferred = 0;
    int rc = libusb_bulk_transfer(hd, 1, (unsigned char*)data, max_data, &transferred, 1024);
    return transferred;
}


static void printbuff(char* buff, int len) {
    int x;
    for (x = 0; x < len; x++) {
        dprintf(3, "%02hhx ", buff[x]);
        if ((x & 15) == 15) dprintf(3, "\n");
    }
    dprintf(3, "\n");
}

// -----------------------------------------------------------------------------------------------
long device_send_cmd(USB_HANDLE device_handle, LP_CMD cmd, void* data, uint32 max_data)
{
    uint8 tx_buf[CMD_BUFSIZE];
    uint32 size;
    int r;
    int transferred = 0;

    size = 0;
    dprintf(2, "Send cmd 0x%x\n", cmd->cmd);
    //refill cmd
    cmd->size = max_data;
    cmd->undef0x04 = 0xEFBEADDE; //0xDEADBEEF as tag, gets noticed in USB dumps :)
    //Standard CBW header
    cmd->id[0] = 'U'; cmd->id[1] = 'S';
    cmd->id[2] = 'B'; cmd->id[3] = 'C';

    //Write the data
    dprintf(2, "Write cmd, 0x1f bytes.\n");
    printbuff((char*)cmd, 0x1f);
    r = libusb_bulk_transfer(device_handle, 1, (unsigned char*)cmd, 0x1f, &transferred, 100);
    if (r < 0 || transferred != 0x1f) {
        fprintf(stderr, "Error @ write cbw (libusb error '%s')\n", libusb_error_name(r));
        return(-1);
    }

    if (max_data > 0) {
        if (cmd->mode == 0x80) {   // read data...
            dprintf(2, "Read data, 0x%x bytes\n", max_data);
            r = libusb_bulk_transfer(device_handle, 0x82, (unsigned char*)data, max_data, &transferred, 1000);
            if (r < 0) {
                fprintf(stderr, "libusb_bulk_transfer(): Read data (libusb error '%s')\n", libusb_error_name(r));
                return(-1);
            }
            size = r;
        }
        else {                  // send data...
            dprintf(2, "Write data, 0x%x bytes\n", max_data);
            r = libusb_bulk_transfer(device_handle, 1, (unsigned char*)data, max_data, &transferred, 1000);
            if (r < 0 || transferred != max_data) {
                fprintf(stderr, "libusb_bulk_transfer(): Write data (libusb error '%s')\n", libusb_error_name(r));
                return(-1);
            }
        }
        dprintf(2, "Done -- 0x%x bytes.\n", r);
    }
    //Read csw
    dprintf(2, "Read csw\n");
    r = libusb_bulk_transfer(device_handle, 0x82, (unsigned char*)tx_buf, 0x0d, &transferred, 100);
    dprintf(2, "Got 0x%x bytes.\n", r);
    dprintf(3, "csw=%s\n", tx_buf);
    if (r < 0) {
        fprintf(stderr, "libusb_bulk_transfer(): Error at read csw (libusb error '%s')\n", libusb_error_name(r));
        return(-1);
    }
    return (long)size;
}
