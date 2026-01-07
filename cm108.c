#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifndef _WIN32
#include <libudev.h>
#include <locale.h>
#include <unistd.h>
#include <regex.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/hidraw.h>
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <setupapi.h>
#include <hidsdi.h>
#include <wchar.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "hid.lib")
#endif

static int cm108_write (char *name, int iomask, int iodata);
int cm108_set_gpio_pin (char *name, int num, int state);

#define CMEDIA_VID 0x0d8c
#define CMEDIA_PID1_MIN 0x0008
#define CMEDIA_PID1_MAX 0x000f

#define CMEDIA_PID_CM108AH   0x0139
#define CMEDIA_PID_CM108B    0x0012
#define CMEDIA_PID_CM119A    0x013a
#define CMEDIA_PID_CM119B    0x0013

#define SSS_VID 0x0c76
#define SSS_PID1 0x1605
#define SSS_PID2 0x1607
#define SSS_PID3 0x160b

#define GOOD_DEVICE(v,p)  ( (v == CMEDIA_VID && ((p >= CMEDIA_PID1_MIN && p <= CMEDIA_PID1_MAX) \
                            || p == CMEDIA_PID_CM108AH \
                            || p == CMEDIA_PID_CM108B \
                            || p == CMEDIA_PID_CM119A \
                            || p == CMEDIA_PID_CM119B )) \
                     || \
                      (v == SSS_VID && (p == SSS_PID1 || p == SSS_PID2 || p == SSS_PID3))  )

int cm108_set_gpio_pin (char *name, int num, int state)
{
    int iomask;
    int iodata;

    if (num < 1 || num > 8) {
      printf("%s CM108 GPIO number %d must be in range of 1 thru 8.\n",
             (name ? name : "(null)"), num);
      return (-1);
    }

    if (state != 0 && state != 1) {
      printf("%s CM108 GPIO state %d must be 0 or 1.\n",
             (name ? name : "(null)"), state);
      return (-1);
    }

    iomask = 1 << (num - 1);
    iodata = state << (num - 1);

    return (cm108_write (name, iomask, iodata));
}

static int cm108_write (char *name, int iomask, int iodata)
{
#ifndef _WIN32
    int fd;
    struct hidraw_devinfo info;
    char io[5];
    int n;

    fd = open (name, O_WRONLY);
    if (fd == -1) {
      printf ("Could not open %s for write, errno=%d\n", name, errno);
      return (-1);
    }

#if 1
    n = ioctl(fd, HIDIOCGRAWINFO, &info);
    if (n == 0) {
      if ( ! GOOD_DEVICE(info.vendor, info.product)) {
        printf ("ioctl HIDIOCGRAWINFO failed for %s. errno = %d.\n", name, errno);
      }
    }
    else {
      printf ("%s is not a supported device type.  Proceed at your own risk.  vid=%04x pid=%04x\n", name, info.vendor, info.product);
    }
#endif

    io[0] = 0;
    io[1] = 0;
    io[2] = iomask;
    io[3] = iodata;
    io[4] = 0;

    n = write (fd, io, sizeof(io));
    if (n != (int)sizeof(io)) {
      printf ("Write to %s failed, n=%d, errno=%d\n", name, n, errno);
      close (fd);
      return (-1);
    }

    close (fd);
    return (0);

#else
    GUID hidGuid;
    HDEVINFO devInfo;
    SP_DEVICE_INTERFACE_DATA devIfData;
    DWORD index = 0;

    HidD_GetHidGuid(&hidGuid);

    devInfo = SetupDiGetClassDevs(&hidGuid, NULL, NULL,
                                  DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (devInfo == INVALID_HANDLE_VALUE) {
        printf("Could not enumerate HID devices on Windows.\n");
        return -1;
    }

    devIfData.cbSize = sizeof(devIfData);

    while (SetupDiEnumDeviceInterfaces(devInfo, NULL, &hidGuid, index, &devIfData)) {
        DWORD requiredSize = 0;
        PSP_DEVICE_INTERFACE_DETAIL_DATA detailData;
        HANDLE h;
        HIDD_ATTRIBUTES attr;
        BOOL ok;
        DWORD written;
        unsigned char io[5];

        SetupDiGetDeviceInterfaceDetail(devInfo, &devIfData,
                                        NULL, 0, &requiredSize, NULL);
        detailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc(requiredSize);
        if (!detailData)
            break;

        detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
        if (!SetupDiGetDeviceInterfaceDetail(devInfo, &devIfData,
                                             detailData, requiredSize,
                                             NULL, NULL)) {
            free(detailData);
            index++;
            continue;
        }

        h = CreateFile(detailData->DevicePath,
                       GENERIC_WRITE | GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            free(detailData);
            index++;
            continue;
        }

        attr.Size = sizeof(attr);
        if (!HidD_GetAttributes(h, &attr)) {
            CloseHandle(h);
            free(detailData);
            index++;
            continue;
        }

        if (!GOOD_DEVICE(attr.VendorID, attr.ProductID)) {
            CloseHandle(h);
            free(detailData);
            index++;
            continue;
        }

        io[0] = 0;
        io[1] = 0;
        io[2] = (unsigned char)iomask;
        io[3] = (unsigned char)iodata;
        io[4] = 0;

        ok = WriteFile(h, io, sizeof(io), &written, NULL);
        if (!ok || written != sizeof(io)) {
            printf("Write to CM108 HID device failed (err=%lu).\n",
                   (unsigned long)GetLastError());
            CloseHandle(h);
            free(detailData);
            SetupDiDestroyDeviceInfoList(devInfo);
            return -1;
        }

        CloseHandle(h);
        free(detailData);
        SetupDiDestroyDeviceInfoList(devInfo);
        return 0;
    }

    SetupDiDestroyDeviceInfoList(devInfo);
    printf("No compatible CM108/SSS HID device found on Windows.\n");
    return -1;
#endif
}

