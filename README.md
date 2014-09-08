# crashblk

This is memory block device driver for IO errors and crash test,
emulating read/write IO error and device crash (or sudden shutdown).

## License

GPLv2 or later.

## Supported kernel version

| Branch   | Kernel version |
|----------|----------------|
| master   | 3.14-          |
| for-3.10 | 3.10-3.14      |

## Build

### Kernel driver

```
> cd crashblk.git/module
> make
> sudo insmod crashblk-mod.ko
```

Use `KERNELDIR`, `DEBUG` make options to customize your build.

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
Internally the module will use 2GiB+ memory.

Delete a device:
```
> sudo crashblkc delete /dev/crashblk0
```

Make a device in error state:
```
> sudo crashblkc make-error /dev/crashblk0 MODE
```
You can specify `MODE` as `r`, `w`, or `rw`.

| Mode | Description    |
|------|----------------|
| `r`  | read IOs fail  |
| `w`  | write IOs fail |
| `rw` | all IOs fail   |

Recover from error state:
```
> sudo crashblkc recover-error /dev/crashblk0
```

Make a device in crash state:
```
> sudo crashblkc make-crash /dev/crashblk0
```

Not flushed data will be lost.

Recover a device from crash state:
```
> sudo crashblkc recover-crash /dev/crashblk0
```

Of course the lost data will not recovered.
Use this for crash test of file systems or so.

-----
