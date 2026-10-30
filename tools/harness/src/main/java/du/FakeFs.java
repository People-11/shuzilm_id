package du;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.file.ByteArrayFileIO;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/** Files libdu reads that unidbg's rootfs lacks or gets wrong. Contents mimic a stock arm64 phone. */
class FakeFs implements IOResolver<AndroidFileIO> {
    static final String HOSTS = "127.0.0.1 localhost\n::1 ip6-localhost\n";
    // 203.0.113.0/24 is TEST-NET-3: resolution succeeds, nothing is ever reachable (HTTP itself is intercepted at the JNI layer)
    static final String HOSTS_RESOLVER = HOSTS + "203.0.113.10 auni.telecome.cn\n";
    final Map<String, byte[]> files = new HashMap<>();

    FakeFs() {
        put("/system/etc/hosts", HOSTS);
    }

    void put(String path, String content) { files.put(path, content.getBytes(StandardCharsets.UTF_8)); }

    @Override
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
        // bionic getaddrinfo opens hosts with O_CLOEXEC; libdu's own hosts dump (field YWu) doesn't. Only the resolver sees the mapping.
        if (pathname.equals("/system/etc/hosts") && (oflags & 0x80000) != 0)
            return FileResult.success(new ByteArrayFileIO(oflags, pathname, HOSTS_RESOLVER.getBytes(StandardCharsets.UTF_8)));
        byte[] data = files.get(pathname);
        return data == null ? null : FileResult.success(new ByteArrayFileIO(oflags, pathname, data));
    }
}
