package du;

import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * RICH=1: the device details AndroidFakes leaves out, so every collector libdu has (fonts / framework listings, file
 * MD5s, stat times, launcher, accessibility, network, ...) finds something and its key shows up in the payload.
 */
final class RichFakes {
    static final Path ROOT = Path.of("target/rootfs/default");

    static void install(Harness h) {
        try { files(); } catch (java.io.IOException e) { throw new RuntimeException(e); }
        Map<String, Bridge.Handler> m = h.br.handlers;
        BaseVM vm = h.vm;

        m.put("android/content/pm/PackageManager->getApplicationLabel(Landroid/content/pm/ApplicationInfo;)Ljava/lang/CharSequence;", (s, a) -> "酷安");
        m.put("android/content/IntentFilter-><init>(Ljava/lang/String;)V", (s, a) -> h.obj("android/content/IntentFilter", a[0]));
        m.put("android/content/Context->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;", (s, a) -> h.obj("android/content/Intent", "sticky"));
        m.put("android/content/Intent->getBooleanExtra(Ljava/lang/String;Z)Z", (s, a) -> false);
        m.put("android/provider/Settings$Global->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;", (s, a) -> {
            String k = ((StringObject) a[1]).getValue();
            h.br.trace.println("RICH Settings.Global " + k);
            return switch (k) { case "adb_enabled", "development_settings_enabled", "stay_on_while_plugged_in" -> "0"; case "device_name" -> "Pixel 7"; default -> null; };
        });

        // accessibility: one enabled service, as an auto-clicker would show up
        m.put("android/service/\"accessibility\"->getEnabledAccessibilityServiceList(I)Ljava/util/List;", (s, a) ->
                h.obj("java/util/List", List.of(h.obj("android/accessibilityservice/AccessibilityServiceInfo", "com.example.clicker/.ClickService"))));
        m.put("java/util/List->size()I", (s, a) -> ((List<?>) s.getValue()).size());
        m.put("java/util/List->get(I)Ljava/lang/Object;", (s, a) -> ((List<?>) s.getValue()).get((Integer) a[0]));
        m.put("java/util/List->toString()Ljava/lang/String;", (s, a) -> String.valueOf(s.getValue()));
        m.put("android/accessibilityservice/AccessibilityServiceInfo->getId()Ljava/lang/String;", (s, a) -> String.valueOf(s.getValue()));

        // wifi / connectivity / telephony
        m.put("android/service/\"wifi\"->getConnectionInfo()Landroid/net/wifi/WifiInfo;", (s, a) -> h.obj("android/net/wifi/WifiInfo", "wi"));
        m.put("FIELD android/net/wifi/WifiInfo->mMacAddress:Ljava/lang/String;", (s, a) -> "02:00:00:00:00:00");
        m.put("android/service/\"wifi\"->getDhcpInfo()Landroid/net/DhcpInfo;", (s, a) -> h.obj("android/net/DhcpInfo", "dhcp"));
        m.put("FIELD android/net/DhcpInfo->ipAddress:I", (s, a) -> 0x1701a8c0);
        m.put("FIELD android/net/DhcpInfo->gateway:I", (s, a) -> 0x0101a8c0);
        m.put("FIELD android/net/DhcpInfo->netmask:I", (s, a) -> 0x00ffffff);
        m.put("android/service/\"connectivity\"->getActiveNetwork()Landroid/net/Network;", (s, a) -> h.obj("android/net/Network", "net100"));
        m.put("android/service/\"connectivity\"->getAllNetworks()[Landroid/net/Network;", (s, a) -> new ArrayObject(h.obj("android/net/Network", "net100")));
        m.put("android/service/\"connectivity\"->getLinkProperties(Landroid/net/Network;)Landroid/net/LinkProperties;", (s, a) -> h.obj("android/net/LinkProperties", "lp"));
        m.put("android/net/LinkProperties->getInterfaceName()Ljava/lang/String;", (s, a) -> "wlan0");
        m.put("android/net/LinkProperties->getHttpProxy()Landroid/net/ProxyInfo;", (s, a) -> null);
        m.put("android/net/LinkProperties->getLinkAddresses()Ljava/util/List;", (s, a) -> h.obj("java/util/List", List.of("fe80::1c2b:3cff:fe4d:5e6f/64", "192.168.1.23/24")));
        m.put("android/net/LinkProperties->getDnsServers()Ljava/util/List;", (s, a) -> h.obj("java/util/List", List.of("/192.168.1.1")));
        m.put("android/service/\"connectivity\"->getNetworkCapabilities(Landroid/net/Network;)Landroid/net/NetworkCapabilities;", (s, a) -> h.obj("android/net/NetworkCapabilities", "nc"));
        m.put("android/net/NetworkCapabilities->toString()Ljava/lang/String;", (s, a) -> "[ Transports: WIFI Capabilities: NOT_METERED&INTERNET&NOT_RESTRICTED&TRUSTED&NOT_VPN&VALIDATED LinkUpBandwidth>=40000Kbps LinkDnBandwidth>=80000Kbps]");
        m.put("android/net/NetworkCapabilities->hasTransport(I)Z", (s, a) -> (Integer) a[0] == Integer.parseInt(System.getenv().getOrDefault("TRANSPORT", "1")));
        m.put("android/net/NetworkCapabilities->getLinkDownstreamBandwidthKbps()I", (s, a) -> 80000);
        m.put("android/net/NetworkCapabilities->getLinkUpstreamBandwidthKbps()I", (s, a) -> 40000);
        m.put("android/service/\"connectivity\"->getMobileDataEnabled()Z", (s, a) -> false);
        m.put("android/service/\"connectivity\"->getActiveNetworkInfo()Landroid/net/NetworkInfo;", (s, a) -> h.obj("android/net/NetworkInfo", "ni"));
        m.put("android/net/NetworkInfo->getTypeName()Ljava/lang/String;", (s, a) -> "WIFI");
        m.put("android/net/NetworkInfo->getSubtypeName()Ljava/lang/String;", (s, a) -> "");
        m.put("android/service/\"phone\"->getSimOperator()Ljava/lang/String;", (s, a) -> "");
        m.put("android/service/\"phone\"->getNetworkOperator()Ljava/lang/String;", (s, a) -> "");
        m.put("android/service/\"phone\"->getSimState()I", (s, a) -> 1);

        // storage
        m.put("android/os/Environment->getDataDirectory()Ljava/io/File;", (s, a) -> h.obj("java/io/File", "/data"));
        m.put("android/os/StatFs-><init>(Ljava/lang/String;)V", (s, a) -> h.obj("android/os/StatFs", a[0]));
        m.put("android/os/StatFs->getAvailableBlocks()I", (s, a) -> 12_345_678);
        m.put("android/os/StatFs->getBlockCount()I", (s, a) -> 30_000_000);
        m.put("android/os/StatFs->getBlockSize()I", (s, a) -> 4096);

        // the INTERNET-holding package list sub_a7ea0 asks for: another app, then us
        m.put("android/content/pm/PackageManager->getPackagesHoldingPermissions([Ljava/lang/String;I)Ljava/util/List;", (s, a) ->
                h.obj("java/util/List", List.of(h.obj("android/content/pm/PackageInfo", "com.tencent.mm"), h.obj("android/content/pm/PackageInfo", Harness.PKG))));
        // launcher (5Nc)
        m.put("android/content/Intent-><init>(Ljava/lang/String;)V", (s, a) -> h.obj("android/content/Intent", a[0]));
        m.put("android/content/Intent->addCategory(Ljava/lang/String;)Landroid/content/Intent;", (s, a) -> s);
        m.put("android/content/pm/PackageManager->resolveActivity(Landroid/content/Intent;I)Landroid/content/pm/ResolveInfo;", (s, a) -> h.obj("android/content/pm/ResolveInfo", "ri"));
        m.put("FIELD android/content/pm/ResolveInfo->activityInfo:Landroid/content/pm/ActivityInfo;", (s, a) -> h.obj("android/content/pm/ActivityInfo", "ai"));
        m.put("FIELD android/content/pm/ActivityInfo->packageName:Ljava/lang/String;", (s, a) -> "com.google.android.apps.nexuslauncher");
    }

    // real files under unidbg's rootfs, so opendir / stat / fopen work on them
    static void files() throws java.io.IOException {
        dir("/system/fonts", "Roboto-Regular.ttf", "NotoSansCJK-Regular.ttc", ".uuid", "DroidSansMono.ttf");
        dir("/system/framework", "framework.jar", "services.jar", "google-common.jar", "ext.jar");
        dir("/vendor/firmware", "a650_gmu.bin", "venus.mbn");
        file("/system/lib/libreference-ril.so", "fake ril");
        file("/system/lib/libc.so", "fake libc32");
        file("/system/lib64/libcutils.so", "fake cutils64");
        for (String d : new String[]{"/data/local/tmp", "/data/system", "/storage/emulated/0/DCIM", "/storage/self/primary",
                "/sdcard/Android/data/com.google.android.gms", "/data/data/" + Harness.PKG + "/shared_prefs"})
            Files.createDirectories(ROOT.resolve(d.substring(1)));
        file("/sdcard/Android/data/.nomedia", "");
        file("/proc/self/cgroup", "0::/uid_10234/pid_12345\n");
        file("/proc/sys/kernel/random/boot_id", "3b0f6e2c-9d41-4a7e-8f15-6c2d9a0b7e44\n");
        file("/proc/self/status", "Name:\tcom.coolapk.market\nState:\tS (sleeping)\nTgid:\t12345\nPid:\t12345\nPPid:\t1000\nTracerPid:\t0\nUid:\t10234\t10234\t10234\t10234\n");
        file("/sys/block/mmcblk0/device/serial", "0x1a2b3c4d\n");
        file("/sys/block/mmcblk0/device/cid", "150100474e3446523401a2b3c4d5e600\n");
        file("/sys/devices/soc0/serial_number", "1234567890\n");
        file("/system/xbin/sugote-mksh", "");
    }

    static void dir(String d, String... names) throws java.io.IOException {
        Path p = ROOT.resolve(d.substring(1));
        Files.createDirectories(p);
        for (String n : names) Files.writeString(p.resolve(n), n, StandardCharsets.UTF_8);
    }

    static void file(String f, String content) throws java.io.IOException {
        Path p = ROOT.resolve(f.substring(1));
        Files.createDirectories(p.getParent());
        Files.writeString(p, content, StandardCharsets.UTF_8);
    }
}
