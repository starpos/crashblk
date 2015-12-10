# crashblk

This is memory block device driver for IO errors and crash test,
emulating read/write IO error and device crash (or sudden shutdown).
This also support configurable delay for read, write and flush IOs.

## License

GPLv2 or later.

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


## Copyright

(C) 2014 Cybozu Labs, Inc.

-----
