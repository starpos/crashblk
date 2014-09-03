# bdevt

This is memory block device for IO errors and crash test,
emulating read/write IO error and crash/recovery.

## License

GPLv2 or later.

## Build

### Kernel driver

```
> cd bdevt.git/module
> make
> sudo insmod bdevt-mod.ko
```

Use `KERNELDIR`, `DEBUG` make options to customize your build.

### Controller

```
> cd bdevt.git/tool
> make
> sudo cp -a bdevtc /usr/local/bin/
```

Use `DEBUG` make option to customize your build.

## Usage

To show command list, type as follows:
```
> bdevtc
```

Create a device with 1GiB:
```
> sudo bdevtc create 1G
0
```

You will get `/dev/bdevt0` of 1GiB size.
Internally the module will use 2GiB+ memory.

Delete a device:
```
> sudo bdevtc delete /dev/bdevt0
```

Make a device in error state:
```
> sudo bdevtc make-error /dev/bdevt0 MODE
```
You can specify `MODE` as `r`, `w`, or `rw`.

| mode | description    |
|------+----------------|
| `r`  | read IOs fail  |
| `w`  | write IOs fail |
| `rw` | all IOs fail   |

Recover from error state:
```
> sudo bdevtc recover-error /dev/bdevt0
```

Make a device in crash state:
```
> sudo bdevtc make-crash /dev/bdevt0
```

Not flushed data will be lost.

Recover a device from crash state:
```
> sudo bdevtc recover-crash /dev/bdevt0
```

Of course the lost data will not recovered.
Use this for crash test of file systems or so.

-----
