package du;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.array.IntArray;
import com.github.unidbg.memory.Memory;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

public class Harness {
    static final String PKG = "com.coolapk.market";
    final AndroidEmulator emu;
    final BaseVM vm;
    final Bridge br;
    final DvmObject<?> ctx;
    long base;
    java.util.Map<String, java.util.Map<String, Object>> prefFiles;
    static final java.util.Set<Long> dumpStr = new java.util.HashSet<>(java.util.List.of(0x147214L));

    /** FNTRACE=<file of function starts, from elf.py funcs>: logs every entry into a libdu function with x0..x2. */
    void hookFunctions(PrintStream trace) {
        try {
            java.util.Set<Long> starts = new java.util.HashSet<>();
            for (String l : java.nio.file.Files.readAllLines(java.nio.file.Path.of(System.getenv("FNTRACE")))) starts.add(Long.decode(l.trim()));
            emu.getBackend().hook_add_new(new com.github.unidbg.arm.backend.BlockHook() {
                @Override public void hookBlock(com.github.unidbg.arm.backend.Backend be, long address, int size, Object user) {
                    long off = address - base;
                    if (starts.contains(off)) {
                        trace.printf("FN %#x x0=%#x x1=%#x x2=%#x lr=%#x%n", off,
                                be.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue(), be.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X1).longValue(),
                                be.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X2).longValue(), be.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue() - base);
                        if (off == 0x136838) { // arg11 (int* status) is the 3rd stack arg; log every write to it
                            long sp = be.reg_read(unicorn.Arm64Const.UC_ARM64_REG_SP).longValue();
                            long st = java.nio.ByteBuffer.wrap(be.mem_read(sp + 16, 8)).order(java.nio.ByteOrder.LITTLE_ENDIAN).getLong();
                            trace.printf("   status@%#x%n", st);
                            be.hook_add_new(new com.github.unidbg.arm.backend.WriteHook() {
                                @Override public void hook(com.github.unidbg.arm.backend.Backend b2, long addr, int sz, long val, Object u) {
                                    trace.printf("   STATUS WRITE %d pc=%#x lr=%#x%n", val, b2.reg_read(unicorn.Arm64Const.UC_ARM64_REG_PC).longValue() - base, b2.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue() - base);
                                }
                                @Override public void onAttach(com.github.unidbg.arm.backend.UnHook u) { }
                                @Override public void detach() { }
                            }, st, st + 4, null);
                        }
                        if (dumpStr.contains(off)) {
                            long p = be.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue();
                            byte[] raw = be.mem_read(p, 256);
                            int n = 0; while (n < raw.length && raw[n] != 0) n++;
                            trace.println("   x0str=" + new String(raw, 0, n, StandardCharsets.ISO_8859_1));
                        }
                    }
                }
                @Override public void onAttach(com.github.unidbg.arm.backend.UnHook u) { }
                @Override public void detach() { }
            }, base, base + 0x1b7000, null);
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    Harness(File so, PrintStream trace) {
        Emu.trace = trace;
        emu = new Emu(PKG);
        emu.getSyscallHandler().setEnableThreadDispatcher(true);
        emu.getSyscallHandler().addIOResolver(new FakeFs());
        Memory mem = emu.getMemory();
        mem.setLibraryResolver(new AndroidResolver(23));
        com.github.unidbg.linux.android.SystemPropertyHook sph = new com.github.unidbg.linux.android.SystemPropertyHook(emu);
        sph.setPropertyProvider(key -> { String v = Props.P.get(key); trace.println("PROP " + key + " => " + v); return v; });
        mem.addHookListener(sph);
        vm = (BaseVM) emu.createDalvikVM();
        br = new Bridge(vm, trace);
        vm.setJni(br.asJni());
        vm.setVerbose(false);
        ctx = vm.resolveClass("android/content/Context").newObject("ctx");
        AndroidFakes.install(this);
        if (System.getenv("RICH") != null) RichFakes.install(this);
        DalvikModule dm = vm.loadLibrary(so, true);
        base = dm.getModule().base;
        if (System.getenv("FNTRACE") != null) hookFunctions(trace);
        // CODEDUMP=off1,off2 : print x0..x30/sp when execution hits these offsets; WATCH=abs : log writes to that address
        if (System.getenv("CODEDUMP") != null) for (String o : System.getenv("CODEDUMP").split(",")) {
            long off = Long.decode(o);
            emu.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                @Override public void hook(com.github.unidbg.arm.backend.Backend be, long address, int size, Object user) {
                    StringBuilder sb = new StringBuilder(String.format("HIT %#x", off));
                    for (int i = 0; i <= 28; i++) sb.append(String.format(" x%d=%#x", i, be.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0 + i).longValue()));
                    sb.append(String.format(" sp=%#x", be.reg_read(unicorn.Arm64Const.UC_ARM64_REG_SP).longValue()));
                    for (int i = 0; i <= 2; i++) try { long p = be.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0 + i).longValue(); if (p > 0x10000) sb.append(" s" + i + "=[" + Emu.cstr(be, p) + "]"); } catch (Exception ignored) { }
                    trace.println(sb);
                }
                @Override public void onAttach(com.github.unidbg.arm.backend.UnHook u) { }
                @Override public void detach() { }
            }, base + off, base + off, null);
        }
        // compress(dest, &destLen, src, srcLen) at these callsites: dump input, then output right after the call returns
        for (long cs : new long[]{0xe53d4, 0xe7fac}) {
            final long[] saved = new long[2];
            emu.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                @Override public void hook(com.github.unidbg.arm.backend.Backend be, long address, int size, Object user) {
                    long off = address - base;
                    if (off == cs) {
                        long dst = be.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue(), dl = be.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X1).longValue();
                        long src = be.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X2).longValue(), sl = be.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X3).longValue();
                        saved[0] = dst; saved[1] = dl;
                        trace.printf("COMPRESS@%#x in[%d]=%s%n", cs, sl, Bridge.hex(be.mem_read(src, (int) sl), 1 << 20));
                    } else {
                        long n = java.nio.ByteBuffer.wrap(be.mem_read(saved[1], 8)).order(java.nio.ByteOrder.LITTLE_ENDIAN).getLong();
                        trace.printf("COMPRESS@%#x ret=%d out[%d]=%s%n", cs, be.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue(), n, Bridge.hex(be.mem_read(saved[0], (int) n), 1 << 20));
                    }
                }
                @Override public void onAttach(com.github.unidbg.arm.backend.UnHook u) { }
                @Override public void detach() { }
            }, base + cs, base + cs + 4, null);
        }
        // NS3=281 : overwrite the last 3 digits of the 2cO time string as sub_14b500 receives it (they pick the field-encoding parameter)
        // NSEC=42 : replace the whole nanosecond part instead (libdu prints it unpadded, so short values move the '.')
        if (System.getenv("NS3") != null || System.getenv("NSEC") != null) {
            byte[] ns3 = System.getenv().getOrDefault("NS3", "").getBytes(StandardCharsets.ISO_8859_1);
            String nsec = System.getenv("NSEC");
            emu.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                @Override public void hook(com.github.unidbg.arm.backend.Backend be, long address, int size, Object user) {
                    long p = be.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue();
                    String s = Emu.cstr(be, p);
                    if (nsec != null) be.mem_write(p, (s.substring(0, s.indexOf('.') + 1) + nsec + "\0").getBytes(StandardCharsets.ISO_8859_1));
                    else if (s.length() >= 3) be.mem_write(p + s.length() - 3, ns3);
                    trace.println("NS3 2cO " + s + " -> " + Emu.cstr(be, p));
                }
                @Override public void onAttach(com.github.unidbg.arm.backend.UnHook u) { }
                @Override public void detach() { }
            }, base + 0x14b500, base + 0x14b500, null);
        }
        if (System.getenv("WATCH") != null) for (String o : System.getenv("WATCH").split(",")) {
            long addr = Long.decode(o);
            emu.getBackend().hook_add_new(new com.github.unidbg.arm.backend.WriteHook() {
                @Override public void hook(com.github.unidbg.arm.backend.Backend b2, long a, int sz, long val, Object u) {
                    trace.printf("WATCH %#x <- %d (%#x) pc=%#x lr=%#x%n", a, val, val, b2.reg_read(unicorn.Arm64Const.UC_ARM64_REG_PC).longValue() - base, b2.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue() - base);
                }
                @Override public void onAttach(com.github.unidbg.arm.backend.UnHook u) { }
                @Override public void detach() { }
            }, addr, addr + 3, null);
        }
        if (System.getenv("PATCH_KEYCHECK") != null) // movn x0,#0 ; ret  -> apiKey format check always "valid"
            emu.getBackend().mem_write(base + 0x147214, new byte[]{0x00, 0x00, (byte) 0x80, (byte) 0x92, (byte) 0xc0, 0x03, 0x5f, (byte) 0xd6});
        dm.callJNI_OnLoad(emu);
        if (System.getenv("NATIVES") != null) // what JNI_OnLoad registered: class, name+signature -> offset
            for (String c : new String[]{"cn/shuzilm/core/DUHelper", "cn/shuzilm/core/Main", "cn/shuzilm/core/AIClient"}) try {
                java.lang.reflect.Field f = DvmClass.class.getDeclaredField("nativesMap"); f.setAccessible(true);
                ((java.util.Map<?, ?>) f.get(vm.resolveClass(c))).forEach((k, v) -> System.out.println("NATIVE " + c + "->" + k + " @" + Long.toHexString(((com.github.unidbg.pointer.UnidbgPointer) v).peer - base)));
            } catch (Exception e) { System.out.println("NATIVE " + c + " " + e); }
    }


    static void wipe(File f) {
        File[] kids = f.listFiles();
        if (kids != null) for (File k : kids) wipe(k);
        f.delete();
    }

    DvmObject<?> obj(String cls, Object v) { return vm.resolveClass(cls).newObject(v); }

    /** Exits if trace.log + unidbg.log stop growing for IDLE seconds (emulator parked on a dead semaphore), or after MAXRUN seconds. */
    static void startWatchdog() {
        long idle = Long.parseLong(System.getenv().getOrDefault("IDLE", "30")) * 1000;
        long maxRun = Long.parseLong(System.getenv().getOrDefault("MAXRUN", "600")) * 1000;
        Thread main = Thread.currentThread();
        Thread wd = new Thread(() -> {
            long start = System.currentTimeMillis(), lastChange = start, lastSize = -1;
            while (true) {
                try { Thread.sleep(1000); } catch (InterruptedException e) { return; }
                long size = new File("trace.log").length() + new File("unidbg.log").length();
                long now = System.currentTimeMillis();
                if (size != lastSize) { lastSize = size; lastChange = now; }
                String why = now - lastChange > idle ? "idle " + (now - lastChange) / 1000 + "s" : now - start > maxRun ? "maxrun" : null;
                if (why != null) {
                    System.out.println("WATCHDOG: " + why + ", main thread at:");
                    for (StackTraceElement e : main.getStackTrace()) System.out.println("    " + e);
                    System.out.flush();
                    Runtime.getRuntime().halt(3);
                }
            }
        }, "watchdog");
        wd.setDaemon(true);
        wd.start();
    }

    public static void main(String[] args) throws Exception {
        startWatchdog();
        if (System.getenv("KEEPFS") == null) wipe(new File("target/rootfs")); // SDK caches IDs on "sdcard"; start each run as a fresh install
        PrintStream trace = new PrintStream(new FileOutputStream("trace.log"), true, StandardCharsets.UTF_8);
        Harness h = new Harness(new File(args.length > 0 ? args[0] : "../../sample/libdu.so"), trace);
        if (System.getenv("FUNCTEST") != null) { // FUNCTEST="0xdf720:abc,0xdf720:0123" -> call fn(char* buf) in place, print buf
            com.github.unidbg.Module mod = h.emu.getMemory().findModule("libdu.so");
            for (String spec : System.getenv("FUNCTEST").split(",")) {
                String[] p = spec.split(":", 2);
                com.github.unidbg.memory.MemoryBlock blk = h.emu.getMemory().malloc(4096, true);
                byte[] in = p[1].getBytes(StandardCharsets.ISO_8859_1);
                blk.getPointer().write(0, java.util.Arrays.copyOf(in, in.length + 1), 0, in.length + 1);
                Number ret = mod.callFunction(h.emu, Long.decode(p[0]), blk.getPointer().peer, in.length);
                System.out.println("FT " + p[0] + " in=[" + p[1] + "] out=[" + blk.getPointer().getString(0) + "] ret=" + Long.toHexString(ret.longValue()));
            }
            return;
        }
        if (System.getenv("KEYTABLE") != null) {
            com.github.unidbg.Module mod = h.emu.getMemory().findModule("libdu.so");
            for (int i = 0; i <= 24; i++) {
                Number p = mod.callFunction(h.emu, 0x142594, i);
                long ptr = p.longValue();
                System.out.println("KEY[" + i + "]=" + (ptr == 0 ? "null" : Emu.cstr(h.emu.getBackend(), ptr)));
            }
            return;
        }
        DvmClass cls = h.vm.resolveClass("cn/shuzilm/core/DUHelper");
        IntArray status = new IntArray(h.vm, new int[1]);
        String config = "{\"apiKey\":\"" + System.getenv().getOrDefault("APIKEY", "<COOLAPK_APIKEY>") /* set APIKEY, or PATCH_KEYCHECK=1 */ + "\",\"pkglist\":\"1\",\"operation\":\"1\",\"cdlmt\":\"1\",\"l_o\":\"1\"}";
        // PREFS_SET="name=value,...": seed <pkg>_prefs with hashed-key raw values (pref mode 3, what the Java side writes)
        if (System.getenv("PREFS_SET") != null) for (String kv : System.getenv("PREFS_SET").split(",")) {
            String[] p2 = kv.split("=", 2);
            String key = java.util.HexFormat.of().withUpperCase().formatHex(java.security.MessageDigest.getInstance("MD5").digest(p2[0].getBytes(StandardCharsets.UTF_8)));
            h.prefFiles.computeIfAbsent(PKG + "_prefs", k -> new java.util.LinkedHashMap<>()).put(key, p2[1]);
        }
        // QUERIES=n: call query n times in one process, so the second sees the prefs / files the first left (later runs of an install)
        for (int q = Integer.parseInt(System.getenv().getOrDefault("QUERIES", "1")); q > 0; q--) {
            trace.println("==== QUERY " + q + " ====");
            DvmObject<?> r = cls.callStaticJniMethodObject(h.emu,
                    "query(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IJJ[I)Ljava/lang/String;",
                    h.ctx, new StringObject(h.vm, config), new StringObject(h.vm, "{\"custom\":\"\"}"),
                    2, Long.parseLong(System.getenv().getOrDefault("A7", "30000")), System.currentTimeMillis(), status);
            System.out.println("RESULT=" + r + " status=" + status.getValue()[0]);
            trace.println("RESULT=" + r + " status=" + status.getValue()[0]);
        }
        // CALLS="sig|arg|arg#sig|..": other DUHelper natives after the queries; args after ctx: strings, or i:<int>
        if (System.getenv("CALLS") != null) for (String c : System.getenv("CALLS").split("#")) {
            String[] cs = c.split("[|]", -1);
            Object[] ca = new Object[cs.length];
            ca[0] = h.ctx;
            for (int i = 1; i < cs.length; i++) ca[i] = cs[i].startsWith("i:") ? (Object) Integer.parseInt(cs[i].substring(2)) : new StringObject(h.vm, cs[i]);
            trace.println("==== CALL " + c + " ====");
            Object r = cs[0].endsWith(")V") ? null : cls.callStaticJniMethodObject(h.emu, cs[0], ca);
            if (cs[0].endsWith(")V")) cls.callStaticJniMethod(h.emu, cs[0], ca);
            System.out.println("CALL " + cs[0] + " => " + r);
        }
        trace.println("==== PREFS ====");
        h.prefFiles.forEach((f, kv) -> kv.forEach((k, v) -> trace.println(f + " | " + k + " = " + v)));
        trace.println("==== MISSES ====");
        h.br.misses.forEach(trace::println);
        System.out.println("misses=" + h.br.misses.size());
    }
}
