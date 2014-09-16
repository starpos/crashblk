/**
 * crashblk.cpp - control crashblk devices.
 *
 * (C) 2014, Cybozu Labs, Inc.
 * @author HOSHINO Takashi <hoshino@labs.cybozu.co.jp>
 */
#include <vector>
#include <string>
#include <sstream>
#include <stdexcept>
#include <iostream>
#include "logger.h"
#include "ioctl.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

using StrVec = std::vector<std::string>;
using Ss = std::stringstream;

const char * const ctlPath = "/dev/crashblk_ctl";

template <typename T>
void unused(T &) {}

class Exception : public std::exception
{
    std::string s_;
public:
    explicit Exception(const std::string &s = "") : s_(s) {}
    const char *what() const noexcept {
        return s_.c_str();
    }
    template <typename T>
    Exception& operator<<(T&& t) {
        std::stringstream ss;
        ss << ":" << std::forward<T>(t);
        s_ += ss.str();
        return *this;
    }
};

uint64_t parseSize(const std::string &s)
{
    if (s.empty()) throw Exception("bad size") << s;
    char *end;
    uint64_t val = ::strtoul(s.data(), &end, 10);
    switch (*end) {
    case 'g': case 'G': val <<= 30; break;
    case 'm': case 'M': val <<= 20; break;
    case 'k': case 'K': val <<= 10; break;
    }
    return val;
}

class File
{
    int fd_;
    public:
    File() : fd_(-1) {}
    ~File() try {
        close();
    } catch (...) {
    }
    int fd() const {
        if (fd_ < 0) throw Exception("bad fd");
        return fd_;
    }
    void open(const std::string &path) {
        if (fd_ >= 0) close();
        fd_ = ::open(path.c_str(), O_RDWR);
        if (fd_ < 0) throw Exception("open failed") << path;
    }
    void close() {
        if (fd_ >= 0) {
            if (::close(fd_) != 0) throw Exception("close failed") << fd_;
            fd_ = -1;
        }
    }
};

void invokeIoctl(const std::string &path, struct crashblk_ctl &ctl)
{
    File file;
    file.open(path);
    if (::ioctl(file.fd(), CRASHBLK_IOCTL, &ctl) < 0) {
        throw Exception("ioctl failed.");
    }
    file.close();
}

void invokeIoctlWithoutParam(const std::string &path, struct crashblk_ctl &ctl, int command)
{
    ::memset(&ctl, 0, sizeof(ctl));
    ctl.command = command;
    invokeIoctl(path, ctl);
}

const std::string& getDevPath(const StrVec &params)
{
    if (params.empty()) throw Exception("specify device.");
    return params[0];
}

void doCreate(const StrVec &params)
{
    if (params.empty()) throw Exception("specify size.");
    const uint64_t sizeLb = parseSize(params[0]) >> 9;

    struct crashblk_ctl ctl = {
        .command = CRASHBLK_IOCTL_START_DEV,
        .val_u64 = sizeLb,
    };
    invokeIoctl(ctlPath, ctl);
    std::cout << ctl.val_u32 << std::endl; // minor id.
}

void doDelete(const StrVec &params)
{
    const std::string &devPath = getDevPath(params);

    struct crashblk_ctl ctl;
    invokeIoctlWithoutParam(devPath, ctl, CRASHBLK_IOCTL_STOP_DEV);
}

void doNumDev(const StrVec &params)
{
    const std::string &devPath = getDevPath(params);

    struct crashblk_ctl ctl;
    invokeIoctlWithoutParam(devPath, ctl, CRASHBLK_IOCTL_NUM_OF_DEV);
    std::cout << ctl.val_int << std::endl; // number of devices.
}

void doGetMajor(const StrVec &)
{
    struct crashblk_ctl ctl;
    invokeIoctlWithoutParam(ctlPath, ctl, CRASHBLK_IOCTL_GET_MAJOR);
    std::cout << ctl.val_int << std::endl; // device major id.
}

void doCrash(const StrVec &params)
{
    const std::string &devPath = getDevPath(params);

    struct crashblk_ctl ctl;
    invokeIoctlWithoutParam(devPath, ctl, CRASHBLK_IOCTL_CRASH);
}

void doIoError(const StrVec &params)
{
    const std::string &devPath = getDevPath(params);

    int state;
    if (params.size() < 2) {
        state = CRASHBLK_STATE_RW_ERROR;
    } else if (params[1] == "rw") {
        state = CRASHBLK_STATE_RW_ERROR;
    } else if (params[1] == "r") {
        state = CRASHBLK_STATE_READ_ERROR;
    } else if (params[1] == "w") {
        state = CRASHBLK_STATE_WRITE_ERROR;
    } else {
        throw Exception("bad mode") << params[1];
    }

    struct crashblk_ctl ctl = {
        .command = CRASHBLK_IOCTL_IO_ERROR,
        .val_int = state,
    };
    invokeIoctl(devPath, ctl);
}

void doRecover(const StrVec &params)
{
    const std::string &devPath = getDevPath(params);

    struct crashblk_ctl ctl;
    invokeIoctlWithoutParam(devPath, ctl, CRASHBLK_IOCTL_RECOVER);
}

void doGetState(const StrVec &params)
{
    const std::string &devPath = getDevPath(params);

    struct crashblk_ctl ctl;
    invokeIoctlWithoutParam(devPath, ctl, CRASHBLK_IOCTL_GET_STATE);
    const int state = ctl.val_int;

    struct Pair {
        int state;
        const char *name;
    } tbl[] = {
        { CRASHBLK_STATE_NORMAL, "normal" },
        { CRASHBLK_STATE_READ_ERROR, "read_error" },
        { CRASHBLK_STATE_WRITE_ERROR, "write_error" },
        { CRASHBLK_STATE_RW_ERROR, "rw_error" },
        { CRASHBLK_STATE_CRASHING, "crashing", },
        { CRASHBLK_STATE_CRASHED, "crashed", },
    };

    for (const Pair &p : tbl) {
        if (p.state == state) {
            std::cout << p.name << std::endl;
            return;
        }
    }
    throw Exception("unknown state") << state;
}

void doSetLostPct(const StrVec &params)
{
    const std::string &devPath = getDevPath(params);

    if (params.size() < 2) {
        throw Exception("percentage must be specified.");
    }
    const int pct = static_cast<int>(parseSize(params[1]));
    if (pct < 0 || pct > 100) {
        throw Exception("percentage must be in the range [0, 100]")
            << devPath << pct;
    }

    struct crashblk_ctl ctl = {
        .command = CRASHBLK_IOCTL_SET_LOST_PCT,
        .val_int = pct,
    };
    invokeIoctl(devPath, ctl);
}

void dispatch(int argc, char *argv[])
{
    struct {
        const char *cmd;
        void (*handler)(const StrVec &);
        const char *helpMsg;
    } tbl[] = {
        {"create", doCreate, "SIZE (with k/m/g)"},
        {"delete", doDelete, "DEV"},
        {"num-dev", doNumDev, ""},
        {"get-major", doGetMajor, ""},
        {"crash", doCrash, "DEV"},
        {"io-error", doIoError, "DEV MODE (r/w/rw)"},
        {"recover", doRecover, "DEV"},
        {"state", doGetState, "DEV"},
        {"set-lost-pct", doSetLostPct, "DEV PCT (0 to 100)"},
    };

    if (argc < 2) {
        Ss ss;
        ss << "Usage:\n";
        for (size_t i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
            ss << "  " << tbl[i].cmd << " " << tbl[i].helpMsg << "\n";
        }
        std::cerr << ss.str();
        ::exit(1);
    }
    const std::string cmd(argv[1]);

    StrVec v;
    for (int i = 2; i < argc; i++) v.push_back(argv[i]);

    for (size_t i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
        if (cmd == tbl[i].cmd) {
            tbl[i].handler(v);
            return;
        }
    }
    throw Exception("command not found") << cmd;
}

int main(int argc, char *argv[]) try
{
    dispatch(argc, argv);
    return 0;
} catch (std::exception &e) {
    LOGe("error: %s\n", e.what());
    return 1;
} catch (...) {
    LOGe("error: unknown error\n");
    return 1;
}
