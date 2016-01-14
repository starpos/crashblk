# crashblk

This is a memory block device driver for IO errors and crash test,
emulating read/write IO error and device crash (or sudden shutdown).
This also supports configurable delay for read, write and flush IOs.

## Features

- Crash emulation.
    - Sudden crash emulation will delete non-persistent data.
- IO error emulation.
    - IO will fail in the error states.
- Configurable response time of read/write/flush IO.
    - You can reproduce various performance behavior of storage devices.

## License

GPLv2 or 3.

## Supported kernel version

| Branch   | Kernel version |
|----------|----------------|
| master   | 4.3-           |
| for-3.14 | 3.14-4.2       |
| for-3.10 | 3.10-3.13      |

## Build

### Kernel driver

```
> cd crashblk.git/module
> make
> sudo insmod crashblk-mod.ko
```

Use `KERNELDIR`, `DEBUG` make options to customize your build.
See module/Makefile for details.


### Controller

```
> cd crashblk.git/tool
> make
> sudo cp -a crashblkc /usr/local/bin/
```

Use `DEBUG` make option to customize your build.

## Usage

To show command list, type as follows:
```
> crashblkc
```

Create a device with 1GiB:
```
> sudo crashblkc create 1G
0
```

You will get `/dev/crashblk0` of 1GiB size.
Internally the module will use 2GiB+ memory
for *cache* and *original data*.

Delete a device:
```
> sudo crashblkc delete /dev/crashblk0
```

You can create two or more devices.

Make a device in error state:
```
> sudo crashblkc io-error /dev/crashblk0 MODE
```
You can specify `MODE` as `r`, `w`, or `rw`.

| Mode | Description    |
|------|----------------|
| `r`  | read IOs fail  |
| `w`  | write IOs fail |
| `rw` | all IOs fail   |

Make a device in crash state:
```
> sudo crashblkc crash /dev/crashblk0
```

Not flushed data will be lost.

Recover a device from crash/io-error state:
```
> sudo crashblkc recover /dev/crashblk0
```

Of course the lost data will not recovered.
Use this for crash test of file systems or so.


Set response times:
```
> sudo crashblkc set-delay-ms /dev/crashblk0 READ_MIN READ_MAX WRITE_MIN WRITE_MAX FLUSH_MIN FLUSH_MAX
```
For each kind of IO, read, write, and flush,
IO response time will be randomly determined between the specified min and max values.
Set both 0 to disable additional delay.

Get response times:
```
> sudo crashblkc get-delay-ms /dev/crashblk0
```

## Copyright

(C) 2014 Cybozu Labs, Inc.

-----
