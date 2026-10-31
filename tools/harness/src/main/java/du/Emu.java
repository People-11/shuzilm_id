package du;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.ARM64SyscallHandler;
import com.github.unidbg.linux.android.AndroidARM64Emulator;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.unix.UnixSyscallHandler;
import unicorn.Arm64Const;

import java.io.PrintStream;
import java.util.Collections;

/** AndroidARM64Emulator with syscall fixups for things unidbg 0.9.9 gets wrong or lacks. */
class Emu extends AndroidARM64Emulator {
    static PrintStream trace = System.out;
    /** When >= 0, clock_gettime/gettimeofday return this many seconds since the epoch. */
    static volatile long fakeTime = -1;

    Emu(String processName) { super(processName, null, Collections.emptyList()); }

    public static String cstr(Backend b, long p) {
        byte[] raw = b.mem_read(p, 512);
        int n = 0; while (n < raw.length && raw[n] != 0) n++;
        return new String(raw, 0, n, java.nio.charset.StandardCharsets.ISO_8859_1);
    }

    // fstatat/readlinkat on "/proc/self/fd/" style paths: unidbg parseInt("") -> NumberFormatException, so -ENOENT
    static Long badFdPath(String pth) {
        return pth.matches("/proc/(self|\\d+)/fd/.*") && !pth.matches("/proc/(self|\\d+)/fd/\\d+") ? Long.valueOf(-2L) : null;
    }

    @Override
    protected UnixSyscallHandler<AndroidFileIO> createSyscallHandler(SvcMemory svcMemory) {
        return new ARM64SyscallHandler(svcMemory) {
            @Override
            public void hook(Backend backend, int intno, int swi, Object user) {
                if (intno == 2) {
                    int nr = backend.reg_read(Arm64Const.UC_ARM64_REG_X8).intValue();
                    if (fakeTime >= 0 && (nr == 113 || nr == 169)) { // clock_gettime(clk, ts) / gettimeofday(tv, tz)
                        long out = backend.reg_read(nr == 113 ? Arm64Const.UC_ARM64_REG_X1 : Arm64Const.UC_ARM64_REG_X0).longValue();
                        byte[] b = java.nio.ByteBuffer.allocate(16).order(java.nio.ByteOrder.LITTLE_ENDIAN).putLong(fakeTime).putLong(0).array();
                        if (out != 0) backend.mem_write(out, b);
                        backend.reg_write(Arm64Const.UC_ARM64_REG_X0, 0L);
                        return;
                    }
                    long x1 = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
                    if (nr == 56) {
                        long x0 = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                        String path = x1 == 0 ? null : cstr(backend, x1);
                        trace.printf("SYSCALL openat dirfd=%d path=%s flags=%#x%n", (int) x0, path, backend.reg_read(Arm64Const.UC_ARM64_REG_X2).longValue());
                    }
                    if ((nr == 48 || nr == 79) && x1 != 0) trace.printf("SYSCALL %s path=%s%n", nr == 48 ? "faccessat" : "fstatat", cstr(backend, x1));
                    Long ret = switch (nr) {
                        // openat: NULL -> -EFAULT; paths unidbg's FilenameUtils.normalize() rejects ("/sdcard/../../..") NPE inside unidbg -> -ENOENT
                        case 56 -> x1 == 0 ? Long.valueOf(-14L) : org.apache.commons.io.FilenameUtils.normalize(cstr(backend, x1), true) == null ? Long.valueOf(-2L) : null;
                        case 48 -> FakeFs.files.containsKey(cstr(backend, x1)) ? Long.valueOf(0L) : null; // faccessat: FAKEFILE paths exist
                        case 79 -> {                             // fstatat: FAKEFILE paths are regular files (mode 0100755, their size)
                            String pth = cstr(backend, x1);
                            byte[] f = FakeFs.files.get(pth);
                            if (f == null) yield badFdPath(pth);
                            byte[] st = new byte[128];
                            java.nio.ByteBuffer.wrap(st).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(16, 0100755).putLong(48, f.length);
                            backend.mem_write(backend.reg_read(Arm64Const.UC_ARM64_REG_X2).longValue(), st);
                            yield 0L; }
                        case 176, 177 -> 10234L;                 // getgid / getegid -> app uid
                        case 158 -> 0L;                          // getgroups -> none
                        // socket: only TCP over AF_INET/6 (libdu's local-port lock) is left to unidbg; everything else -EACCES
                        case 198 -> { long dom = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue(), type = x1 & 0xf;
                                      trace.printf("SYSCALL socket domain=%d type=%d%n", dom, type);
                                      yield (dom == 2 || dom == 10) && type == 1 ? null : Long.valueOf(-13L); }
                        case 199 -> -13L;                        // socketpair
                        case 167 -> switch (backend.reg_read(Arm64Const.UC_ARM64_REG_X0).intValue()) {
                            case 21 -> Long.valueOf(2L);         // PR_GET_SECCOMP: app processes run in filter mode
                            case 39 -> Long.valueOf(0L);         // PR_GET_NO_NEW_PRIVS: zygote has CAP_SYS_ADMIN, so 0
                            default -> null; };
                        case 78 -> badFdPath(cstr(backend, x1));
                        case 203 -> {                            // connect: never reach the outside world; log the target
                            long sa = x1; byte[] b = backend.mem_read(sa, 8);
                            int fam = (b[0] & 0xff) | (b[1] & 0xff) << 8, port = (b[2] & 0xff) << 8 | (b[3] & 0xff);
                            trace.printf("SYSCALL connect family=%d port=%d addr=%d.%d.%d.%d -> ECONNREFUSED%n", fam, port, b[4] & 0xff, b[5] & 0xff, b[6] & 0xff, b[7] & 0xff);
                            yield -111L; }
                        case 206 -> -101L;                       // sendto -> ENETUNREACH
                        default -> null;
                    };
                    if (ret != null) {
                        if (nr == 56) trace.println("SYSCALL openat -> " + ret);
                        backend.reg_write(Arm64Const.UC_ARM64_REG_X0, ret);
                        return;
                    }
                }
                // RICH: unidbg leaves stat times 0, and libdu skips those fields; give atime / mtime a real-looking value
                int nr = intno == 2 ? backend.reg_read(Arm64Const.UC_ARM64_REG_X8).intValue() : -1;
                long statBuf = nr == 79 ? backend.reg_read(Arm64Const.UC_ARM64_REG_X2).longValue() : 0;
                super.hook(backend, intno, swi, user);
                if (statBuf != 0 && System.getenv("RICH") != null && backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue() == 0) {
                    byte[] t = java.nio.ByteBuffer.allocate(32).order(java.nio.ByteOrder.LITTLE_ENDIAN)
                            .putLong(1760001234L).putLong(123456789L).putLong(1750004321L).putLong(987654321L).array();
                    backend.mem_write(statBuf + 72, t); // st_atim, st_mtim
                }
            }
        };
    }
}
