//loadram.c: main source code, uploads binary file to ZRAM
//Copyright 2006 Jeroen Domburg <s1fwx@jeroen.ietsmet.nl>
//This software is licensed under the GNU GPL.

#include "loadram.h"
#include "debug.h"


static unsigned char giveio[] =
{
  0xC3, 0xFD, 0x34, 0x3E, 0xF7, 0xD3, 0x05, 0x3A,
  0xDE, 0x35, 0xB7, 0x20, 0x30, 0xDB, 0x70, 0xE6,
  0xCF, 0xD3, 0x70, 0x3E, 0x03, 0xD3, 0x60, 0x3E,
  0x3F, 0xD3, 0x66, 0xAF, 0xD3, 0x61, 0x7C, 0xD3,
  0x62, 0x7D, 0xD3, 0x63, 0x78, 0xD3, 0x64, 0x79,
  0xD3, 0x65, 0xDB, 0x68, 0xE6, 0x08, 0x28, 0xFA,
  0xDB, 0x68, 0xE6, 0x08, 0x20, 0xFA, 0xDB, 0x70,
  0xF6, 0x30, 0xD3, 0x70, 0xC9, 0x3E, 0x01, 0xD3,
  0x58, 0x3E, 0x28, 0xD3, 0x5A, 0x3E, 0xFF, 0xD3,
  0x5C, 0x79, 0xD3, 0x63, 0x78, 0xD3, 0x64, 0xAF,
  0xD3, 0x65, 0x7D, 0xD3, 0x89, 0x7C, 0xD3, 0x8A,
  0xAF, 0xD3, 0x51, 0x3C, 0xD3, 0x51, 0xC5, 0x06,
  0x03, 0x10, 0xFE, 0xDB, 0x51, 0xCB, 0x47, 0x20,
  0xFA, 0x06, 0x0A, 0x10, 0xFE, 0xC1, 0x3E, 0x01,
  0xD3, 0x58, 0x3E, 0x20, 0xD3, 0x5A, 0xC9, 0x3E,
  0xF7, 0xD3, 0x05, 0x3A, 0xDE, 0x35, 0xB7, 0x20,
  0x30, 0xDB, 0x70, 0xE6, 0xCF, 0xD3, 0x70, 0x3E,
  0x04, 0xD3, 0x60, 0x3E, 0x3F, 0xD3, 0x66, 0xAF,
  0xD3, 0x61, 0x7C, 0xD3, 0x62, 0x7D, 0xD3, 0x63,
  0x78, 0xD3, 0x64, 0x79, 0xD3, 0x65, 0xDB, 0x68,
  0xE6, 0x10, 0x28, 0xFA, 0xDB, 0x68, 0xE6, 0x10,
  0x20, 0xFA, 0xDB, 0x70, 0xF6, 0x30, 0xD3, 0x70,
  0xC9, 0x3E, 0x02, 0xD3, 0x58, 0x3E, 0x04, 0xD3,
  0x5A, 0x79, 0xD3, 0x63, 0x78, 0xD3, 0x64, 0xAF,
  0xD3, 0x65, 0x7D, 0xD3, 0x89, 0x7C, 0xD3, 0x8A,
  0x3E, 0x02, 0xD3, 0x51, 0x3C, 0xD3, 0x51, 0xC5,
  0x06, 0x03, 0x10, 0xFE, 0xC1, 0xDB, 0x51, 0xCB,
  0x47, 0x20, 0xFA, 0xDB, 0x5B, 0xCB, 0x4F, 0x28,
  0xFA, 0x3E, 0x02, 0xD3, 0x58, 0x3E, 0x20, 0xD3,
  0x5A, 0xC9, 0xAF, 0xD3, 0x01, 0xD3, 0x02, 0x11,
  0x00, 0x80, 0x21, 0x00, 0xA0, 0x06, 0x20, 0x1A,
  0x96, 0xC0, 0x10, 0xFB, 0xC9, 0xF3, 0xED, 0x56,
  0xAF, 0xD3, 0x27, 0xD3, 0x4E, 0xD3, 0xF0, 0x31,
  0xF8, 0x37, 0xCD, 0xEA, 0x34, 0x32, 0xDE, 0x35,
  0xB7, 0x28, 0x04, 0x3E, 0x09, 0xD3, 0x04, 0x21,
  0x9C, 0x35, 0xE5, 0x21, 0x00, 0x00, 0x01, 0x1F,
  0x00, 0xCD, 0x03, 0x34, 0x21, 0x00, 0x40, 0x7E,
  0xFE, 0x55, 0x20, 0xEF, 0x23, 0x7E, 0xFE, 0x53,
  0x20, 0xE9, 0x23, 0x7E, 0xFE, 0x42, 0x20, 0xE3,
  0x23, 0x7E, 0xFE, 0x43, 0x20, 0xDD, 0xED, 0x4B,
  0x08, 0x40, 0x78, 0xB1, 0x28, 0x22, 0x3A, 0x0C,
  0x40, 0xE6, 0x80, 0x20, 0x35, 0x21, 0x20, 0x00,
  0xCD, 0x03, 0x34, 0x3A, 0x0F, 0x40, 0xFE, 0x64,
  0xCA, 0x52, 0x36, 0xFE, 0x6D, 0xCA, 0x05, 0x36,
  0xFE, 0x58, 0xCA, 0x17, 0x36, 0xC3, 0xD0, 0x35,
  0x3A, 0x0F, 0x40, 0xFE, 0x70, 0xCA, 0xF2, 0x35,
  0xFE, 0x6D, 0xCA, 0x0F, 0x36, 0xFE, 0x58, 0xCA,
  0x1A, 0x36, 0xFE, 0x52, 0xCA, 0x20, 0x36, 0xC3,
  0xD0, 0x35, 0x3A, 0x0F, 0x40, 0xFE, 0x64, 0xCA,
  0x26, 0x36, 0xFE, 0x6D, 0xCA, 0xFC, 0x35, 0xFE,
  0x70, 0xCA, 0xE8, 0x35, 0xFE, 0x69, 0xCA, 0xD1,
  0x35, 0xC3, 0xD0, 0x35, 0xED, 0x4B, 0x08, 0x40,
  0x78, 0xB1, 0x28, 0x0D, 0x3A, 0x0C, 0x40, 0xE6,
  0x80, 0x28, 0x06, 0x21, 0x20, 0x00, 0xCD, 0x77,
  0x34, 0x3E, 0x53, 0x32, 0x03, 0x40, 0xAF, 0x32,
  0x0C, 0x40, 0x47, 0x4F, 0xED, 0x43, 0x08, 0x40,
  0xED, 0x43, 0x0A, 0x40, 0x21, 0x00, 0x00, 0x01,
  0x0D, 0x00, 0xCD, 0x77, 0x34, 0xC3, 0x17, 0x35,
  0xC9, 0x21, 0xDD, 0x35, 0x11, 0x20, 0x40, 0x01,
  0x0B, 0x00, 0xED, 0xB0, 0xC9, 0x31, 0x00, 0x73,
  0x31, 0x67, 0x69, 0x76, 0x65, 0x69, 0x6F, 0x00,
  0x3A, 0x10, 0x40, 0x4F, 0xED, 0x78, 0x32, 0x20,
  0x40, 0xC9, 0x3A, 0x10, 0x40, 0x4F, 0x3A, 0x11,
  0x40, 0xED, 0x79, 0xC9, 0x2A, 0x10, 0x40, 0x11,
  0x20, 0x40, 0xED, 0xB0, 0xC9, 0x21, 0x20, 0x40,
  0xED, 0x5B, 0x10, 0x40, 0xED, 0xB0, 0xC9, 0x2A,
  0x10, 0x40, 0x3A, 0x12, 0x40, 0x77, 0xC9, 0xCD,
  0x05, 0x36, 0xED, 0x5B, 0x10, 0x40, 0xD5, 0xC9,
  0x3E, 0x88, 0xD3, 0x4E, 0x18, 0xFE, 0x21, 0x10,
  0x40, 0x7E, 0x23, 0xD3, 0x06, 0x7E, 0x23, 0xD3,
  0x07, 0x7E, 0x23, 0xD3, 0x08, 0x7E, 0x23, 0xD3,
  0x09, 0x7E, 0x23, 0xD3, 0x0A, 0x3E, 0x20, 0xD3,
  0x0B, 0x3E, 0x00, 0xD3, 0x0C, 0xAF, 0xD3, 0x0D,
  0x3E, 0x40, 0xD3, 0x0E, 0x3E, 0x07, 0xD3, 0x0F,
  0x18, 0x2A, 0x3E, 0x20, 0xD3, 0x06, 0x3E, 0x00,
  0xD3, 0x07, 0xAF, 0xD3, 0x08, 0x3E, 0x40, 0xD3,
  0x09, 0x3E, 0x07, 0xD3, 0x0A, 0x21, 0x10, 0x40,
  0x7E, 0x23, 0xD3, 0x0B, 0x7E, 0x23, 0xD3, 0x0C,
  0x7E, 0x23, 0xD3, 0x0D, 0x7E, 0x23, 0xD3, 0x0E,
  0x7E, 0x23, 0xD3, 0x0F, 0x7E, 0xD3, 0x12, 0x0B,
  0x79, 0xF6, 0x01, 0xD3, 0x10, 0x78, 0xD3, 0x11,
  0x3E, 0x01, 0xD3, 0x13, 0xDB, 0x13, 0xCB, 0x47,
  0x20, 0xFA, 0xC9, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x28, 0x63, 0x29, 0x77, 0x69, 0x52, 0x65
};


//Small debugging routine to display the contents of a buffer
static void printbuff(char* buff, int len) {
    int x;
    for (x = 0; x < len; x++) {
        dprintf(3, "%02hhx ", buff[x]);
        if ((x & 15) == 15) dprintf(3, "\n");
    }
    dprintf(3, "\n");
}

//The following code contains quite a few 'magic numbers'. These are gleaned
//from usb logs from a firmware update by the original Windows-programs.
//I'm not sure if all the magic really is necessary, but let's keep it until
//we're sure.


//Doesn't work yet. The big idea is to find out if we're in firmware or ADFU 
//mode completely automatically
int inadfumode(USB_HANDLE h) {
    CMD c;
    size_t n;
    char data[1024];
    memset(&c, 0, sizeof(CMD));
    dprintf(1, "Inquire device type...\n");
    //Inquire device type
    c.mode = 0x80;
    c.cmd = 0x08008905;
    c.size = 0xc0;
    c.unkwn0x13 = (8 << 16) + 0xcb03;
    c.unkwn0x17 = (uint32)(0x4100 + (c.size >> 8));;
    device_send_cmd(h, &c, (void*)data, c.size);
    printbuff(data, c.size);
    for (n = 0; n < c.size; n++) {
        if (data[n] > 31) dprintf(3, "%c", data[n]);
    }
    dprintf(3, "\n");
    return(0);
}

int uploadtoram(USB_HANDLE h, char* buff, unsigned int address, unsigned int nobytes) {
    //Upload program to RAM
    CMD c;
    memset(&c, 0, sizeof(CMD));
    c.mode = 0x0;
    c.cmd = 0x3005 + ((long)address << 16);
    c.size = (uint32)nobytes;
    c.unkwn0x13 = (8 << 16) + 0xcb03; //page 0
    c.unkwn0x17 = (uint32)(0x4100 + (nobytes >> 8));
    return device_send_cmd(h, &c, (void*)buff, (uint32)nobytes);
}

//Makes the player run a block of code from a certain address.
int runcode(struct usb_dev_handle* h, unsigned int addr, int adfumode) {
    CMD c;
    memset(&c, 0, sizeof(CMD));
    if (!adfumode) {
        c.mode = 0xf8;
        c.cmd = 0xa0000020 + (addr << 8);
        c.size = 0;
        c.unkwn0x13 = 0x80000;
        c.unkwn0x17 = 0xe57000;
        return device_send_cmd(h, &c, NULL, 0);
    }
    else {
        c.mode = 0xf8;
        c.cmd = 0x9f000010 + (addr << 8);
        c.size = 0;
        c.unkwn0x13 = 0x0240000;
        c.unkwn0x17 = 0xe57000;
        return device_send_cmd(h, &c, NULL, 0);
    }
}

//Load a file and return the buffer containing it. The buffer will be
//padded to a multiple of pad bytes.
char* loadfile(char* filename, unsigned int* size, unsigned int pad) {
    size_t r;
    FILE* f;
    char* buff;
    unsigned int nobytes;
    struct stat fstat;

    //Get file size
    r = stat(filename, &fstat);
    if (r != 0) {
        perror("Statting input file");
        return(0);
    }

    if (fstat.st_size > 65535) {
        printf("Files >64K don't fit in the z80 address space, silly.\n");
        return(0);
    }
    nobytes = fstat.st_size;

    //Pad to a multiple of pad bytes.
    nobytes += (pad - 1); nobytes = ((int)(nobytes / pad)) * pad;
    dprintf(2, "%li bytes; padded to %i (0x%x).\n", fstat.st_size, nobytes, nobytes);

    //Alloc buffer & read
    buff = (char*)malloc(nobytes);
    if (buff == NULL) {
        perror("Malloc failed");
        return(0);
    }

    f = fopen(filename, "rb");
    if (!f) {
        perror("Reading input file");
        return(0);
    }
    r = fread(buff, 1, fstat.st_size, f);
    if ((int)r < fstat.st_size) {
        perror("Short read at input file");
        return(0);
    }
    dprintf(2, "%i bytes read.\n", nobytes);
    fclose(f);
    *size = nobytes;
    return(buff);
}


void printhelp() {
    printf("Usage: \nloadram file.bin [options]\nor\n");
    printf("loadram 2ndloader.bin file.bin [options]\n");
    printf("with valid options:\n");
    printf("-h: display this help blurb\n");
    printf("-u: use adfu mode instead of firmware update mode\n");
    printf("-d n: set debugging verbosity to n\n");
    exit(0);
}


#pragma once
#include <windows.h>
#include <setupapi.h>   //also needs "setupapi.lib"
#pragma comment(lib, "setupapi.lib")

DWORD adfudevicewin_enumerate(void)
{
    const unsigned char ucADFU[16] =
    {
      0x40, 0x81, 0xB1, 0xBD, 0x71, 0x75, 0xD7, 0x11,
      0x96, 0xC6, 0x52, 0x54, 0xAB, 0x1A, 0xFF, 0x33
    };

    HDEVINFO hDevInf = SetupDiGetClassDevsA((CONST GUID*)ucADFU, 0, NULL, 0x12);
    if (hDevInf == INVALID_HANDLE_VALUE)
    {
		fprintf(stderr, "SetupDiGetClassDevs failed, last error %d\n", GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    for (DWORD dwIndex = 0; 1; dwIndex++)
    {
        SP_DEVICE_INTERFACE_DATA data;
        data.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
        if (!SetupDiEnumDeviceInterfaces(hDevInf, NULL, (CONST GUID*)ucADFU, dwIndex, &data))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS) break;
            SetupDiDestroyDeviceInfoList(hDevInf);
            fprintf(stderr, "SetupDiEnumDeviceInterfaces failed, last error %d\n", GetLastError());
            return INVALID_HANDLE_VALUE;
        }

        DWORD dwSize = 0;
        if (!SetupDiGetDeviceInterfaceDetailA(hDevInf, &data, NULL, 0, &dwSize, NULL))
        {
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            {
                SetupDiDestroyDeviceInfoList(hDevInf);
                fprintf(stderr, "SetupDiGetDeviceInterfaceDetailA failed, last error %d\n", GetLastError());
                return INVALID_HANDLE_VALUE;
            }
        }
        dwSize += sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_A);

        char* lpBuf = (char*)malloc(dwSize);
        PSP_DEVICE_INTERFACE_DETAIL_DATA_A lpDetail = (PSP_DEVICE_INTERFACE_DETAIL_DATA_A)lpBuf;
        lpDetail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_A);
        if (!SetupDiGetDeviceInterfaceDetailA(hDevInf, &data, lpDetail, dwSize, NULL, NULL))
        {
            DWORD dwError = GetLastError();
            SetupDiDestroyDeviceInfoList(hDevInf);
            free(lpBuf);
            fprintf(stderr, "SetupDiGetDeviceInterfaceDetailA failed, last error %d\n", GetLastError());
            return INVALID_HANDLE_VALUE;
        }
		printf("DevicePath: %s\n", lpDetail->DevicePath);
        free(lpBuf);
    }

    SetupDiDestroyDeviceInfoList(hDevInf);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
#define ADFU_MAX_DATA_LENGTH 0x4000
#define ADFU_TIMEOUT 5

typedef struct _SCSI_PASS_THROUGH {
    uint16 Length;                //Contains the sum of the length of the SCSI_PASS_THROUGH structure and the lengths of the accompanying data and request sense buffers. 
    uint8  ScsiStatus;            //Reports the SCSI status that was returned by the HBA or the target device. 
    uint8  PathId;                //Indicates the SCSI port or bus for the request. 
    uint8  TargetId;              //Indicates the target controller or device on the bus. 
    uint8  Lun;                   //Indicates the logical unit number of the device. 
    uint8  CdbLength;             //Indicates the size in bytes of the SCSI command descriptor block. 
    uint8  SenseInfoLength;       //Indicates the size in bytes of the request-sense buffer. 
    uint8  DataIn;                //Indicates whether the SCSI command will read or write data. This field must have one of three values: SCSI_IOCTL_DATA_IN (write to device), SCSI_IOCTL_DATA_OUT (read from device), SCSI_IOCTL_DATA_UNSPECIFIED
    uint32 DataTransferLength;    //Indicates the size in bytes of the data buffer. If an underrun occurs, the miniport must update this member to the number of bytes actually transferred.
    uint32 TimeOutValue;          //Indicates the interval in seconds that the request can execute before the OS-specific port driver might consider it timed out.
    uint32 DataBufferOffset;      //Contains an offset from the beginning of this structure to the data buffer.
    uint32 SenseInfoOffset;       //Offset from the beginning of this structure to the request-sense buffer.
    uint8  Cdb[16];               //Specifies the SCSI command descriptor block to be sent to the target device.
} SCSI_PASS_THROUGH, * PSCSI_PASS_THROUGH;

enum DIR { IO_READ, IO_WRITE };

unsigned int adfuioctlwin_wrd(HANDLE hDevice, const void* lp, unsigned int u)
{
    DWORD dwRet = 0;
    if (hDevice == INVALID_HANDLE_VALUE)
    {
		fprintf(stderr, "hDevice == INVALID_HANDLE_VALUE\n");
		return 0;
    }
    if (!DeviceIoControl(hDevice, /*IOCTL_SCSI_PASS_THROUGH*/ 0x4D004,
        (LPVOID)lp, u, (LPVOID)lp, u, &dwRet, NULL))
    {
		fprintf(stderr, "DeviceIoControl failed, last error %d\n", GetLastError());
		return 0;
    }
    return dwRet;
}

unsigned int adfuioctlwin_io(HANDLE hDevice, enum DIR nDir, const void* lpCdb, unsigned char uCdbLength,
    void* lpData, unsigned int uDataLength, unsigned int uTimeout)
{
    struct {
        SCSI_PASS_THROUGH header;
        char sense[4];
        char data[ADFU_MAX_DATA_LENGTH];
    } iob;

    if (uCdbLength > sizeof(iob.header.Cdb))
    {
		fprintf(stderr, "uCdbLength > sizeof(iob.header.Cdb)\n");
        return 0;
    //    throw AdfuException(ERROR_INVALID_PARAMETER); //uCdbLength = sizeof(iob.header.Cdb);
    }
    if (uDataLength > ADFU_MAX_DATA_LENGTH)
    {
		fprintf(stderr, "uDataLength > ADFU_MAX_DATA_LENGTH\n");
        return 0;
        //throw AdfuException(ERROR_INVALID_PARAMETER); //uDataLength = ADFU_MAX_DATA_LENGTH;
    }

    memset(&iob, 0, sizeof(iob));
    iob.header.Length = sizeof(iob.header);
    //iob.header.PathId = 0;
    iob.header.TargetId = 1;
    //iob.header.Lun = 0;
    //iob.header.SenseInfoLength = 0;
    iob.header.DataTransferLength = uDataLength;
    iob.header.TimeOutValue = (uTimeout > 0) ? uTimeout : 0xFFFF;
    iob.header.DataBufferOffset = (ULONG)((ULONGLONG)&iob.data - (ULONGLONG)&iob);
    iob.header.SenseInfoOffset = (ULONG)((ULONGLONG)&iob.sense - (ULONGLONG)&iob);

    if (nDir == IO_READ) iob.header.DataIn = 1; //= SCSI_IOCTL_DATA_OUT
    else if (lpData != NULL && uDataLength > 0) memcpy(&iob.data, lpData, uDataLength); //= SCSI_IOCTL_DATA_IN

    if (lpCdb != NULL && uCdbLength > 0)
    {
        iob.header.CdbLength = uCdbLength;
        memcpy(iob.header.Cdb, lpCdb, uCdbLength);
    }

    unsigned int uResult = adfuioctlwin_wrd(hDevice, &iob, sizeof(iob));
    if (nDir == IO_READ && lpData != NULL && uDataLength > 0) memcpy((void*)lpData, iob.data, uDataLength);

    return iob.header.DataTransferLength;
}

HANDLE adfuioctlwin_preopen(LPCSTR name)
{
	HANDLE hDevice = CreateFileA(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL, OPEN_EXISTING, 0, NULL);

    if (hDevice == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "CreateFile failed, last error %d\n", GetLastError());
		return INVALID_HANDLE_VALUE;
	}

    DWORD dwRet = 0;
    char cBuf[256];
    if (!DeviceIoControl(hDevice, /*IOCTL_DISK_GET_DRIVE_GEOMETRY*/ 0x70000, NULL, 0, cBuf, sizeof(cBuf), &dwRet, NULL))
    {
		CloseHandle(hDevice);
		fprintf(stderr, "DeviceIoControl failed, last error %d\n", GetLastError());
		return INVALID_HANDLE_VALUE;
    }

    if (!dwRet)
    {
        CloseHandle(hDevice);
        fprintf(stderr, "DeviceIoControl failed (dwRet), last error %d\n", GetLastError());
        return INVALID_HANDLE_VALUE;
    }
    if (((DWORD*)cBuf)[2] != 0x0000000B)
    {
        CloseHandle(hDevice);
        fprintf(stderr, "cBuf[2] is not what I was looking for\n");
        return INVALID_HANDLE_VALUE;
    }

    const uint32 uCmdInit[3] = { 0xCC, 0, 0 };
    adfuioctlwin_io(hDevice, IO_READ, uCmdInit, sizeof(uCmdInit), cBuf, 11, 3);
    if (strncmp(cBuf, "ACTIONSUSBD", 11) != 0)
    {
        CloseHandle(hDevice);
        fprintf(stderr, "DeviceIoControl failed, last error %d\n", GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    return hDevice;
}

HANDLE adfuioctlwin_open(LPCSTR name)
{
	HANDLE hDevice = adfuioctlwin_preopen(name);

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        return hDevice;
    }

    //put device into fw mode now
    uint8 uResult = 0;
    const uint32 uCmdEnterFMode[3] = { 0xCB, 0, 0 };
    for (int nRepeat = 10; nRepeat > 0; nRepeat--)
    {
        Sleep(1000);
        if ((adfuioctlwin_io(hDevice, IO_READ, uCmdEnterFMode, sizeof(uCmdEnterFMode), &uResult, 1, 3) == 1) && (uResult == 0xFF))
        {
            Sleep(500);
            return hDevice;
        }
    }

    return hDevice;
}

HANDLE adfuioctlwin_enumerate(void)
{
    DWORD dwDrives = GetLogicalDrives();
    for (char cDrive = 'A'; cDrive <= 'Z'; cDrive++, dwDrives >>= 1) if (dwDrives & 1)
    {
        char drive[MAX_PATH] = { '\0' };
		snprintf(drive, sizeof(drive), "\\\\.\\%c:", cDrive);
		HANDLE hDrive = adfuioctlwin_preopen(drive);
		
        if (hDrive != INVALID_HANDLE_VALUE)
		{
            printf("Drive: %s seems to be valid!!!!\n", drive);

            CloseHandle(hDrive);

			printf("Switching to firmware mode...\n");
			hDrive = adfuioctlwin_open(drive);
			if (hDrive == INVALID_HANDLE_VALUE)
			{
				printf("Failed to switch to firmware mode\n");
				continue;
			}
            printf("Drive switched!\n");
            return hDrive;
		}
    }
}

enum MEMSEL { IPM_L = 0, IPM_M = 1, IPM_H = 2, IDM_L = 4, IDM_M = 5, IDM_H = 6, ZRAM2 = 7, ZRAM1 = 8, ZRAM = 8 };

unsigned int adfuioctlwin_uploadBlock(HANDLE hDevice, unsigned int uAddress,
    const void* lpData, unsigned int uDataLength,
    enum MEMSEL nMemSel)
{
    if (uDataLength > ADFU_MAX_DATA_LENGTH) uDataLength = ADFU_MAX_DATA_LENGTH;
    unsigned int uBlockLength = (uDataLength + 3) & 0xFFFFFFFC;

    uint8 uBuf[ADFU_MAX_DATA_LENGTH];
    memset(uBuf, 0, sizeof(uBuf));
    memcpy(uBuf, lpData, uDataLength);

    //
    // command: r/w memory
    // cdb[0]   command id (0x05)
    // cdb[1]   command flags (0x80 = read, 0x00 = write)
    // cdb[3:2] source/destination address
    // cdb[6]   memory select (0..7 = IPM/IDM/ZRAM2, 8 = ZRAM)
    // cdb[8:7] data length
    //
    uint32 uCmd[3] = { 0x0005 | (((uint16)uAddress) << 16),
      ((uint8)uBlockLength << 24) + (((uint8)nMemSel) << 16), uBlockLength >> 8 };
    unsigned int uResult = adfuioctlwin_io(hDevice, IO_WRITE, uCmd, sizeof(uCmd), uBuf, uBlockLength, 3);
    //

    return (uResult > uDataLength) ? uDataLength : uResult;
}

unsigned int adfuioctlwin_upload(HANDLE hDevice, unsigned int uAddress,
    const void* lpData, unsigned int uDataLength, enum MEMSEL nMemSel)
{
    unsigned int uResult = 0;

	printf("adfuioctlwin_upload(): Uploading %u bytes to address 0x%08X\n", uDataLength, uAddress);
    for (; uDataLength > ADFU_MAX_DATA_LENGTH; uDataLength -= ADFU_MAX_DATA_LENGTH)
    {
        uResult += adfuioctlwin_uploadBlock(hDevice, uAddress, lpData, ADFU_MAX_DATA_LENGTH, nMemSel);
        uAddress += ADFU_MAX_DATA_LENGTH;
        lpData = &((uint8*)lpData)[ADFU_MAX_DATA_LENGTH];
    }

    if (uDataLength > 0) uResult += adfuioctlwin_uploadBlock(hDevice, uAddress, lpData, uDataLength, nMemSel);

    return uResult;
}

void adfuioctlwin_exec(HANDLE hDevice, unsigned int uAddress, unsigned int uTimeout, BOOL fRecoveryMode)
{
    //
    // command: call address
    // cdb[0]   command id (0x10/0x20)
    // cdb[2:1] destination address
    //
    uint32 uCmd[3] = { (fRecoveryMode ? 0x10 : 0x20) | (((uint16)uAddress) << 8), 0, 0 };
	printf("adfuioctlwin_exec(): Executing address 0x%08X\n", uAddress);
    adfuioctlwin_io(hDevice, IO_WRITE, uCmd, sizeof(uCmd), NULL, 0, uTimeout);
}

#if 0
#define GIVEIO_ADDR 0x3400
#define GIVEIO_MAX_DATA_LENGTH 0xA00  //0xFE0 on old devices, 0xC00 on v9 devices, but actually only 0xA00 works

/* upload giveio */
adfuioctlwin_upload(adfuHandle, GIVEIO_ADDR, giveio, sizeof(giveio), ZRAM);
/* run giveio */
adfuioctlwin_exec(adfuHandle, GIVEIO_ADDR, 5, FALSE);
//verify giveio
#pragma pack(1)
struct {
    uint8 version;
    uint8 v9flag;
    char  id[15];
} info;
#pragma pack()

adfuioctlwin_io(adfuHandle, IO_READ, "i", 1, &info, sizeof(info), 3);
if (strcmp(info.id, "s1giveio") != 0)
{
    printf("Failed to execute GIVEIO!\n");
}
else
{
    uint8 uVersion;
    bool fV9Device;
    uVersion = info.version;
    fV9Device = (info.v9flag != 0);

    printf("s1giveio stub uploaded, info.version %u, info.v9 %d", info.version, info.v9flag);
}

#endif

int main(int argc, char** argv) {
    static struct usb_dev_handle* h;
    int r = 0;
    int n;
    char* membuff = NULL;
    char* files[2];
    int useadfu = 0;
    int nofiles = 0;
    size_t nobytes = 0;
    unsigned int toaddr;

    //0x3400 is an ECC checking scratchpad, so we should be able to safely use it
    toaddr = 0x3400;



    if (argc == 1) printhelp();

    debug_verbosity = 1;
    for (n = 1; n < argc; n++) {
        if (strcmp(argv[n], "-u") == 0) {
            useadfu = 1;
        }
        else if (strcmp(argv[n], "-h") == 0) {
            printhelp();
        }
        else if (strcmp(argv[n], "-d") == 0) {
            if (n == argc - 1) printhelp();
            n++;
            debug_verbosity = atoi(argv[n]);
        }
        else {
            if (nofiles == 2) printhelp();
            files[nofiles++] = argv[n];
        }
    }

    if (nofiles == 0) printhelp();

    if (nofiles == 2) {
        //2nd stage loader gets loaded higher, to allow for bigger program
        //uploads without overwriting the loader.
        toaddr = 0x3800;
    }

    if (useadfu) {
        //adfu mode
        //h = adfuioctlwin_enumerate();
        HANDLE adfuHandle = adfuioctlwin_enumerate();
        if (adfuHandle == INVALID_HANDLE_VALUE)
        {
            printf("No ADFU device found or an error occurred.\n");
            exit(1);
        }


        //load file...
        membuff = loadfile(files[0], &nobytes, 0x100);
        /* upload giveio */
        adfuioctlwin_upload(adfuHandle, toaddr, membuff, nobytes, ZRAM);
        /* run giveio */
        adfuioctlwin_exec(adfuHandle, toaddr, 5, FALSE);

		printf("Done.\n");
        CloseHandle(adfuHandle);
        return 0;
    }

        


    //Open libusb handle to device
    h = device_open();
    if (h == NULL) {
        printf("\nNo device found or an error occurred.\n");
        exit(1);
    }

    //load file...
    membuff = loadfile(files[0], &nobytes, 0x100);
    //upload...
    uploadtoram(h, membuff, toaddr, nobytes);
    //and run.
    dprintf(1, "Running the program...\n");
    runcode(h, toaddr, useadfu);

    if (nofiles == 1) {
        //The uploaded bin already was what's needed. Exit.
        dprintf(1, "Done.\n");
        exit(0);
    }

    dprintf(1, "Loading data to send to second stage loader...\n");
    //Alloc buffer & read
    free(membuff);
    membuff = loadfile(files[1], &nobytes, 0x3800);    //don't change 3rd arg, the 2nd 
    //stage loader triggers on having received 0x3800 bytes.

    dprintf(1, "Uploading second binary...\n");
    int transferred = 0;
    r = libusb_bulk_transfer(h, 0x1, (char*)membuff, nobytes, &transferred, 10000);

    if (r < 0) {
        perror("Error sending");
    }
    else {
        dprintf(2, "Sent %i bytes.\n", r);
    }
    dprintf(1, "Done\n");
    device_close(h);
    return(0);
}
