package du;

import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.Map;

/** Minimal fake Android world for libdu. Values mimic a plain Pixel-like device. */
final class AndroidFakes {
    static final String DATA = "/data/user/0/" + Harness.PKG;

    static void install(Harness h) {
        Bridge b = h.br;
        Map<String, Bridge.Handler> m = b.handlers;
        BaseVM vm = h.vm;

        // --- DUHelper static fields the SDK reads/writes ---
        b.staticFields.put("cn/shuzilm/core/DUHelper->mPopu:I", 0);
        b.staticFields.put("cn/shuzilm/core/DUHelper->mPort:I", 17835);
        b.staticFields.put("cn/shuzilm/core/DUHelper->mMeic:I", 0);
        b.staticFields.put("cn/shuzilm/core/DUHelper->mContext:Landroid/content/Context;", h.ctx);

        // --- Context ---
        m.put("android/content/Context->getPackageName()Ljava/lang/String;", (s, a) -> Harness.PKG);
        m.put("android/content/Context->getApplicationContext()Landroid/content/Context;", (s, a) -> h.ctx);
        m.put("android/content/Context->getFilesDir()Ljava/io/File;", (s, a) -> h.obj("java/io/File", DATA + "/files"));
        m.put("android/content/Context->getCacheDir()Ljava/io/File;", (s, a) -> h.obj("java/io/File", DATA + "/cache"));
        m.put("android/content/Context->getExternalCacheDir()Ljava/io/File;", (s, a) -> h.obj("java/io/File", "/storage/emulated/0/Android/data/" + Harness.PKG + "/cache"));
        m.put("android/content/Context->getDir(Ljava/lang/String;I)Ljava/io/File;", (s, a) -> h.obj("java/io/File", DATA + "/app_" + a[0]));
        m.put("android/content/Context->getDatabasePath(Ljava/lang/String;)Ljava/io/File;", (s, a) -> h.obj("java/io/File", DATA + "/databases/" + a[0]));
        m.put("android/content/Context->getApplicationInfo()Landroid/content/pm/ApplicationInfo;", (s, a) -> h.obj("android/content/pm/ApplicationInfo", "appinfo"));
        m.put("android/content/Context->getPackageManager()Landroid/content/pm/PackageManager;", (s, a) -> h.obj("android/content/pm/PackageManager", "pm"));
        m.put("android/content/Context->getContentResolver()Landroid/content/ContentResolver;", (s, a) -> h.obj("android/content/ContentResolver", "cr"));
        m.put("android/content/Context->getSystemService(Ljava/lang/String;)Ljava/lang/Object;", (s, a) -> h.obj("android/service/" + a[0], a[0]));
        m.put("android/content/Context->checkSelfPermission(Ljava/lang/String;)I", (s, a) -> -1);
        m.put("android/content/Context->checkPermission(Ljava/lang/String;II)I", (s, a) -> -1);

        java.util.Set<String> granted = java.util.Set.of("android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE", "android.permission.ACCESS_WIFI_STATE");
        m.put("android/content/pm/PackageManager->checkPermission(Ljava/lang/String;Ljava/lang/String;)I", (s, a) -> granted.contains(((StringObject) a[0]).getValue()) ? 0 : -1);
        m.put("android/bluetooth/BluetoothAdapter->getDefaultAdapter()Landroid/bluetooth/BluetoothAdapter;", (s, a) -> null);

        // ApplicationInfo fields
        m.put("FIELD android/content/pm/ApplicationInfo->dataDir:Ljava/lang/String;", (s, a) -> DATA);
        m.put("FIELD android/content/pm/ApplicationInfo->sourceDir:Ljava/lang/String;", (s, a) -> "/data/app/~~abc==/" + Harness.PKG + "-xyz==/base.apk");
        m.put("FIELD android/content/pm/ApplicationInfo->publicSourceDir:Ljava/lang/String;", (s, a) -> "/data/app/~~abc==/" + Harness.PKG + "-xyz==/base.apk");
        m.put("FIELD android/content/pm/ApplicationInfo->nativeLibraryDir:Ljava/lang/String;", (s, a) -> "/data/app/~~abc==/" + Harness.PKG + "-xyz==/lib/arm64");
        m.put("FIELD android/content/pm/ApplicationInfo->flags:I", (s, a) -> 0x38be44);
        m.put("FIELD android/content/pm/ApplicationInfo->targetSdkVersion:I", (s, a) -> 34);
        m.put("FIELD android/content/pm/ApplicationInfo->uid:I", (s, a) -> 10234);

        // PackageManager / PackageInfo
        m.put("FIELD android/content/pm/PackageInfo->firstInstallTime:J", (s, a) -> 1760000000000L);
        // LUT_SEQ="v1,v2,...": successive lastUpdateTime reads (the last repeats), to tell getPackageInfo from the installed list
        final String[] lutSeq = System.getenv().getOrDefault("LUT_SEQ", "1760000000000").split(",");
        final int[] lutN = {0};
        m.put("FIELD android/content/pm/PackageInfo->lastUpdateTime:J", (s, a) -> Long.parseLong(lutSeq[Math.min(lutN[0]++, lutSeq.length - 1)]));
        m.put("FIELD android/content/pm/PackageInfo->versionCode:I", (s, a) -> 2510151);
        m.put("FIELD android/content/pm/PackageInfo->versionName:Ljava/lang/String;", (s, a) -> "15.5.1");
        m.put("FIELD android/content/pm/PackageInfo->packageName:Ljava/lang/String;", (s, a) -> String.valueOf(s.getValue()));
        m.put("FIELD android/content/pm/PackageInfo->applicationInfo:Landroid/content/pm/ApplicationInfo;", (s, a) -> h.obj("android/content/pm/ApplicationInfo", "appinfo"));
        m.put("android/content/pm/PackageInfo->getLongVersionCode()J", (s, a) -> 2510151L);

        // java.io.File (never real host FS)
        m.put("java/io/File-><init>(Ljava/lang/String;)V", (s, a) -> h.obj("java/io/File", ((StringObject) a[0]).getValue()));
        m.put("java/io/File->getAbsolutePath()Ljava/lang/String;", (s, a) -> String.valueOf(s.getValue()));
        m.put("java/io/File->getPath()Ljava/lang/String;", (s, a) -> String.valueOf(s.getValue()));
        m.put("java/io/File->exists()Z", (s, a) -> true);
        m.put("java/io/File->mkdirs()Z", (s, a) -> true);
        m.put("java/io/File->length()J", (s, a) -> { byte[] f = FakeFs.files.get(String.valueOf(s.getValue())); return f == null ? 0L : (long) f.length; });

        // System
        m.put("java/lang/System->currentTimeMillis()J", (s, a) -> System.currentTimeMillis());
        m.put("java/lang/System->getProperty(Ljava/lang/String;)Ljava/lang/String;", (s, a) -> {
            String k = ((StringObject) a[0]).getValue();
            return switch (k) { case "java.vm.version" -> "2.1.0"; case "os.arch" -> "aarch64"; case "http.agent" -> "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 7 Build/UQ1A.240205.004)"; default -> null; };
        });
        m.put("android/os/SystemClock->elapsedRealtime()J", (s, a) -> 3_600_000L);
        m.put("android/os/SystemClock->uptimeMillis()J", (s, a) -> 3_500_000L);
        m.put("android/os/SystemClock->elapsedRealtimeNanos()J", (s, a) -> 3_600_000_000_000L);
        m.put("android/os/Process->myPid()I", (s, a) -> 12345);
        m.put("android/os/Process->myUid()I", (s, a) -> 10234);

        // Build
        Map<String, Object> build = new HashMap<>();
        build.put("MODEL", "Pixel 7"); build.put("BRAND", "google"); build.put("MANUFACTURER", "Google");
        build.put("DEVICE", "panther"); build.put("PRODUCT", "panther"); build.put("BOARD", "panther");
        build.put("HARDWARE", "panther"); build.put("FINGERPRINT", "google/panther/panther:14/UQ1A.240205.004/11269751:user/release-keys");
        build.put("ID", "UQ1A.240205.004"); build.put("DISPLAY", "UQ1A.240205.004"); build.put("HOST", "abfarm-release-2004-0151");
        build.put("TAGS", "release-keys"); build.put("TYPE", "user"); build.put("USER", "android-build");
        build.put("BOOTLOADER", "cloudripper-1.0-11104286"); build.put("SERIAL", "unknown"); build.put("RADIO", "g5300q-231215-240112-B-11313143");
        build.forEach((k, v) -> b.staticFields.put("android/os/Build->" + k + ":Ljava/lang/String;", new StringObject(vm, (String) v)));
        b.staticFields.put("android/os/Build->TIME:J", 1704200000000L);
        b.staticFields.put("android/os/Build$VERSION->SDK_INT:I", 34);
        b.staticFields.put("android/os/Build$VERSION->RELEASE:Ljava/lang/String;", new StringObject(vm, "14"));
        b.staticFields.put("android/os/Build$VERSION->INCREMENTAL:Ljava/lang/String;", new StringObject(vm, "11269751"));
        b.staticFields.put("android/os/Build$VERSION->SECURITY_PATCH:Ljava/lang/String;", new StringObject(vm, "2024-02-05"));
        b.staticFields.put("android/os/Build$VERSION->CODENAME:Ljava/lang/String;", new StringObject(vm, "REL"));

        // --- SharedPreferences: real in-memory maps keyed by file name (optionally pre-seeded from PREFS_SEED) ---
        Map<String, Map<String, Object>> prefFiles = new HashMap<>();
        java.util.function.Function<String, Map<String, Object>> prefFile = n -> prefFiles.computeIfAbsent(n, k -> new java.util.LinkedHashMap<>());
        h.prefFiles = prefFiles;
        m.put("android/content/Context->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;", (s, a) -> {
            String n = ((StringObject) a[0]).getValue(); prefFile.apply(n); return h.obj("android/content/SharedPreferences", n); });
        java.util.function.Function<DvmObject<?>, Map<String, Object>> pf = o -> prefFile.apply(String.valueOf(o.getValue()));
        m.put("android/content/SharedPreferences->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", (s, a) -> {
            Object v = pf.apply(s).get(((StringObject) a[0]).getValue()); return v != null ? v : a[1]; });
        m.put("android/content/SharedPreferences->getInt(Ljava/lang/String;I)I", (s, a) -> { Object v = pf.apply(s).get(((StringObject) a[0]).getValue()); return v instanceof Integer ? v : a[1]; });
        m.put("android/content/SharedPreferences->getLong(Ljava/lang/String;J)J", (s, a) -> { Object v = pf.apply(s).get(((StringObject) a[0]).getValue()); return v instanceof Long ? v : a[1]; });
        m.put("android/content/SharedPreferences->getBoolean(Ljava/lang/String;Z)Z", (s, a) -> { Object v = pf.apply(s).get(((StringObject) a[0]).getValue()); return v instanceof Boolean ? v : a[1]; });
        m.put("android/content/SharedPreferences->contains(Ljava/lang/String;)Z", (s, a) -> pf.apply(s).containsKey(((StringObject) a[0]).getValue()));
        m.put("android/content/SharedPreferences->edit()Landroid/content/SharedPreferences$Editor;", (s, a) -> h.obj("android/content/SharedPreferences$Editor", s.getValue()));
        m.put("android/content/SharedPreferences$Editor->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;", (s, a) -> {
            pf.apply(s).put(((StringObject) a[0]).getValue(), a[1] == null ? null : ((StringObject) a[1]).getValue()); return s; });
        m.put("android/content/SharedPreferences$Editor->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;", (s, a) -> { pf.apply(s).put(((StringObject) a[0]).getValue(), a[1]); return s; });
        m.put("android/content/SharedPreferences$Editor->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;", (s, a) -> { pf.apply(s).put(((StringObject) a[0]).getValue(), a[1]); return s; });
        m.put("android/content/SharedPreferences$Editor->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;", (s, a) -> { pf.apply(s).put(((StringObject) a[0]).getValue(), a[1]); return s; });
        m.put("android/content/SharedPreferences$Editor->remove(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;", (s, a) -> { pf.apply(s).remove(((StringObject) a[0]).getValue()); return s; });
        m.put("android/content/SharedPreferences$Editor->apply()V", (s, a) -> null);
        m.put("android/content/SharedPreferences$Editor->commit()Z", (s, a) -> true);

        // Not installed: real PackageManager throws NameNotFoundException (libdu treats any non-null result as "installed")
        Bridge.Handler notFound = (s, a) -> { vm.throwException(vm.resolveClass("android/content/pm/PackageManager$NameNotFoundException").newObject(null)); return null; };
        // INSTALLED="pkg1,pkg2": other packages that look installed (same fake PackageInfo / ApplicationInfo as ours)
        java.util.Set<String> installed = new java.util.HashSet<>(java.util.List.of(System.getenv().getOrDefault("INSTALLED", "").split(",")));
        installed.add(Harness.PKG);
        m.put("android/content/pm/PackageManager->getApplicationIcon(Ljava/lang/String;)Landroid/graphics/drawable/Drawable;", (s, a) ->
                installed.contains(((StringObject) a[0]).getValue()) ? h.obj("android/graphics/drawable/Drawable", "icon") : notFound.handle(s, a));
        m.put("android/content/pm/PackageManager->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;", (s, a) -> {
            String pkg = ((StringObject) a[0]).getValue();
            return installed.contains(pkg) ? h.obj("android/content/pm/PackageInfo", pkg) : notFound.handle(s, a); });
        m.put("android/content/pm/PackageManager->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;", (s, a) ->
                installed.contains(((StringObject) a[0]).getValue()) ? h.obj("android/content/pm/ApplicationInfo", "appinfo") : notFound.handle(s, a));

        // --- Signing certificate: the real Coolapk v2 cert (coolapk_cert.der) ---
        byte[] cert;
        try { cert = java.nio.file.Files.readAllBytes(java.nio.file.Path.of("coolapk_cert.der")); } catch (java.io.IOException e) { throw new RuntimeException(e); }
        java.util.function.Supplier<DvmObject<?>> sigs = () -> new com.github.unidbg.linux.android.dvm.array.ArrayObject(h.obj("android/content/pm/Signature", cert));
        m.put("FIELD android/content/pm/PackageInfo->signatures:[Landroid/content/pm/Signature;", (s, a) -> sigs.get());
        m.put("FIELD android/content/pm/PackageInfo->signingInfo:Landroid/content/pm/SigningInfo;", (s, a) -> h.obj("android/content/pm/SigningInfo", "si"));
        m.put("FIELD android/content/pm/PackageInfo->signingInfo:[Landroid/content/pm/SigningInfo;", (s, a) -> h.obj("android/content/pm/SigningInfo", "si"));
        m.put("android/content/pm/SigningInfo->hasMultipleSigners()Z", (s, a) -> false);
        m.put("android/content/pm/SigningInfo->hasPastSigningCertificates()Z", (s, a) -> false);
        m.put("android/content/pm/SigningInfo->getApkContentsSigners()[Landroid/content/pm/Signature;", (s, a) -> sigs.get());
        m.put("android/content/pm/SigningInfo->getSigningCertificateHistory()[Landroid/content/pm/Signature;", (s, a) -> sigs.get());
        m.put("android/content/pm/Signature->toByteArray()[B", (s, a) -> ((byte[]) s.getValue()).clone());
        m.put("android/content/pm/Signature->toCharsString()Ljava/lang/String;", (s, a) -> java.util.HexFormat.of().formatHex((byte[]) s.getValue()));
        m.put("android/content/pm/Signature->hashCode()I", (s, a) -> java.util.Arrays.hashCode((byte[]) s.getValue()));

        // --- Stable per-"device" identifiers derived from DEVICE_SEED ---
        String seed = System.getenv().getOrDefault("DEVICE_SEED", "1");
        byte[] widevine = sha256("widevine:" + System.getenv().getOrDefault("SEED_WV", seed));                        // 32 bytes like a real deviceUniqueId
        String androidId = System.getenv().getOrDefault("ANDROID_ID", java.util.HexFormat.of().formatHex(sha256("aid:" + System.getenv().getOrDefault("SEED_AID", seed))).substring(0, 16));
        m.put("android/media/MediaDrm-><init>(Ljava/util/UUID;)V", (s, a) -> h.obj("android/media/MediaDrm", "widevine"));
        m.put("android/media/MediaDrm->getPropertyByteArray(Ljava/lang/String;)[B", (s, a) ->
                "deviceUniqueId".equals(((StringObject) a[0]).getValue()) ? new ByteArray(vm, widevine.clone()) : new ByteArray(vm, new byte[0]));
        m.put("android/media/MediaDrm->getPropertyString(Ljava/lang/String;)Ljava/lang/String;", (s, a) -> switch (((StringObject) a[0]).getValue()) {
            case "vendor" -> "Google"; case "version" -> "17.0.0"; case "algorithms" -> "AES/CBC/NoPadding,HmacSHA256"; case "securityLevel" -> "L1"; default -> ""; });
        m.put("android/media/MediaDrm->close()V", (s, a) -> null);
        m.put("android/media/MediaDrm->release()V", (s, a) -> null);
        m.put("android/provider/Settings$Secure->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;", (s, a) -> {
            String k = ((StringObject) a[1]).getValue();
            return switch (k) { case "android_id" -> androidId; case "default_input_method" -> "com.google.android.inputmethod.latin/com.android.inputmethod.latin.LatinIME"; default -> null; }; });

        // --- Reflection on classes: Class objects are DvmClass ---
        m.put("java/lang/Class->forName(Ljava/lang/String;)Ljava/lang/Class;", (s, a) -> vm.resolveClass(((StringObject) a[0]).getValue().replace('.', '/')));
        m.put("java/lang/Class->forName(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;", (s, a) -> vm.resolveClass(((StringObject) a[0]).getValue().replace('.', '/')));
        m.put("java/lang/ClassLoader->loadClass(Ljava/lang/String;)Ljava/lang/Class;", (s, a) -> vm.resolveClass(((StringObject) a[0]).getValue().replace('.', '/')));
        m.put("java/lang/Class->getName()Ljava/lang/String;", (s, a) -> ((DvmClass) s).getClassName().replace('/', '.'));
        m.put("java/lang/Class->getSimpleName()Ljava/lang/String;", (s, a) -> { String n = ((DvmClass) s).getClassName(); return n.substring(n.lastIndexOf('/') + 1); });
        // NATIVE="android.telephony.TelephonyManager#getImei,...": reflection sees these methods as native (as a hook leaves them)
        java.util.List<String> natives = java.util.List.of(System.getenv().getOrDefault("NATIVE", "").split(","));
        m.put("java/lang/Class->getDeclaredMethods()[Ljava/lang/reflect/Method;", (s, a) -> {
            String cls = s instanceof DvmClass c ? c.getClassName().replace('/', '.') : "";
            return new com.github.unidbg.linux.android.dvm.array.ArrayObject(natives.stream().filter(n -> n.startsWith(cls + "#"))
                    .map(n -> h.obj("java/lang/reflect/Method", n)).toArray(DvmObject[]::new)); });
        m.put("java/lang/reflect/Method->getName()Ljava/lang/String;", (s, a) -> String.valueOf(s.getValue()).substring(String.valueOf(s.getValue()).indexOf('#') + 1));
        m.put("java/lang/reflect/Method->getModifiers()I", (s, a) -> 0x101); // public native
        m.put("java/lang/Class->getDeclaredFields()[Ljava/lang/reflect/Field;", (s, a) -> new com.github.unidbg.linux.android.dvm.array.ArrayObject());
        m.put("java/lang/Class->getClassLoader()Ljava/lang/ClassLoader;", (s, a) -> h.obj("dalvik/system/PathClassLoader", "app-loader"));
        m.put("java/lang/reflect/Proxy->isProxyClass(Ljava/lang/Class;)Z", (s, a) -> false);
        m.put("java/lang/ClassLoader->getParent()Ljava/lang/ClassLoader;", (s, a) -> "app-loader".equals(s.getValue()) ? h.obj("java/lang/BootClassLoader", "boot-loader") : null);
        m.put("java/lang/Object->getClass()Ljava/lang/Class;", (s, a) -> s.getObjectType());
        m.put("*->getClass()Ljava/lang/Class;", (s, a) -> s.getObjectType());

        // --- TLS trust managers (pinning / JustTrustMe checks): behave like a stock device ---
        m.put("javax/net/ssl/TrustManagerFactory->getDefaultAlgorithm()Ljava/lang/String;", (s, a) -> "PKIX");
        m.put("javax/net/ssl/TrustManagerFactory->getInstance(Ljava/lang/String;)Ljavax/net/ssl/TrustManagerFactory;", (s, a) -> h.obj("javax/net/ssl/TrustManagerFactory", "tmf"));
        m.put("javax/net/ssl/TrustManagerFactory->init(Ljava/security/KeyStore;)V", (s, a) -> null);
        m.put("javax/net/ssl/TrustManagerFactory->getTrustManagers()[Ljavax/net/ssl/TrustManager;", (s, a) ->
                new com.github.unidbg.linux.android.dvm.array.ArrayObject(h.obj("android/security/net/config/RootTrustManager", "tm")));
        m.put("java/security/KeyStore->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;", (s, a) -> h.obj("java/security/KeyStore", ((StringObject) a[0]).getValue()));
        m.put("java/security/KeyStore->load(Ljava/security/KeyStore$LoadStoreParameter;)V", (s, a) -> null);
        // USERCA="alias=issuer,...": user-installed CA certificates in AndroidCAStore (aliases start with "user:")
        java.util.Map<String, String> userCa = new java.util.LinkedHashMap<>();
        for (String kv : System.getenv().getOrDefault("USERCA", "").split(",")) if (kv.contains("=")) userCa.put(kv.substring(0, kv.indexOf('=')), kv.substring(kv.indexOf('=') + 1));
        m.put("java/security/KeyStore->aliases()Ljava/util/Enumeration;", (s, a) -> h.obj("java/util/Enumeration",
                java.util.Collections.enumeration("AndroidCAStore".equals(s.getValue()) ? userCa.keySet() : java.util.List.<String>of())));
        m.put("java/util/Enumeration->hasMoreElements()Z", (s, a) -> ((java.util.Enumeration<?>) s.getValue()).hasMoreElements());
        m.put("java/util/Enumeration->nextElement()Ljava/lang/Object;", (s, a) -> String.valueOf(((java.util.Enumeration<?>) s.getValue()).nextElement()));
        m.put("java/security/KeyStore->getCertificate(Ljava/lang/String;)Ljava/security/cert/Certificate;", (s, a) ->
                h.obj("java/security/cert/X509Certificate", userCa.getOrDefault(((StringObject) a[0]).getValue(), "")));
        m.put("java/security/cert/X509Certificate->getIssuerDN()Ljava/security/Principal;", (s, a) -> h.obj("java/security/Principal", s.getValue()));
        m.put("java/security/Principal->getName()Ljava/lang/String;", (s, a) -> String.valueOf(s.getValue()));

        // --- Network: capture, never send ---
        m.put("java/net/URL-><init>(Ljava/lang/String;)V", (s, a) -> { h.br.trace.println("NET URL " + Bridge.show(a[0])); return h.obj("java/net/URL", ((StringObject) a[0]).getValue()); });
        m.put("java/net/URL->openConnection()Ljava/net/URLConnection;", (s, a) -> h.obj("java/net/HttpURLConnection", new Conn(String.valueOf(s.getValue()))));
        m.put("java/net/HttpURLConnection->getOutputStream()Ljava/io/OutputStream;", (s, a) -> h.obj("java/io/OutputStream", ((Conn) s.getValue()).body));
        m.put("java/io/OutputStream->write([B)V", (s, a) -> { byte[] d = ((ByteArray) a[0]).getValue(); ((ByteArrayOutputStream) s.getValue()).write(d); h.br.trace.println("NET BODY " + Bridge.show(a[0])); return null; });
        m.put("java/net/HttpURLConnection->setRequestMethod(Ljava/lang/String;)V", (s, a) -> { ((Conn) s.getValue()).method = ((StringObject) a[0]).getValue(); return null; });
        m.put("java/net/HttpURLConnection->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V", (s, a) -> {
            ((Conn) s.getValue()).headers.put(((StringObject) a[0]).getValue(), ((StringObject) a[1]).getValue()); return null; });
        m.put("java/net/HttpURLConnection->getResponseCode()I", (s, a) -> {
            Conn c = (Conn) s.getValue();
            h.br.trace.println("NET SEND " + c + " headers=" + c.headers);
            return Resp.code(); // never sent: the reply is RESP_JSON / RESP_RAW_HEX, else a 599
        });
        m.put("java/net/HttpURLConnection->getInputStream()Ljava/io/InputStream;", (s, a) -> {
            Conn c = (Conn) s.getValue();
            return h.obj("java/io/InputStream", new java.io.ByteArrayInputStream(c.resp != null ? c.resp : Resp.body(c.url))); });
        m.put("java/io/InputStream->read([BII)I", (s, a) -> {
            byte[] dst = ((ByteArray) a[0]).getValue();
            int n = ((java.io.InputStream) s.getValue()).read(dst, (Integer) a[1], (Integer) a[2]);
            h.br.trace.println("NET RECV " + n);
            return n;
        });
        m.put("java/io/InputStream->read([B)I", (s, a) -> ((java.io.InputStream) s.getValue()).read(((ByteArray) a[0]).getValue()));
        m.put("java/io/InputStream->close()V", (s, a) -> null);
    }

    /** Fake server reply: RESP_JSON env -> XOR KEY[16]; RESP_RAW_HEX -> raw bytes; else 599. */
    static final class Resp {
        static final byte[] KEY = "xp7j@&!v5]2k#+3z{n9$q^r%[8f1*d4e:c>0l?m/6)yb-=w}".getBytes();
        static byte[] xor(byte[] in) { byte[] o = in.clone(); for (int i = 0; i < o.length; i++) o[i] ^= KEY[i % KEY.length]; return o; }
        static int code() { return System.getenv("RESP_JSON") != null || System.getenv("RESP_RAW_HEX") != null ? 200 : 599; }
        static byte[] body(String url) {
            String raw = System.getenv("RESP_RAW_HEX");
            if (raw != null) return java.util.HexFormat.of().parseHex(raw);
            String json = System.getenv("RESP_JSON");
            if (json == null) return new byte[0];
            byte[] out = json.getBytes(java.nio.charset.StandardCharsets.UTF_8); // reply is XOR only (sub_e999c), no zlib
            for (int i = 0; i < out.length; i++) out[i] ^= KEY[i % KEY.length];
            return out;
        }
    }

    static byte[] sha256(String x) {
        try { return java.security.MessageDigest.getInstance("SHA-256").digest(x.getBytes(java.nio.charset.StandardCharsets.UTF_8)); }
        catch (java.security.NoSuchAlgorithmException e) { throw new RuntimeException(e); }
    }

    static final class Conn {
        final String url; final ByteArrayOutputStream body = new ByteArrayOutputStream();
        String method = "GET"; final Map<String, String> headers = new java.util.LinkedHashMap<>();
        int code; byte[] resp;
        Conn(String url) { this.url = url; }

        @Override public String toString() { return "Conn(" + url + ", body=" + body.size() + ")"; }
    }
}
