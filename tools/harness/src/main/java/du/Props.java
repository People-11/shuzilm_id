package du;

import java.util.HashMap;
import java.util.Map;

/** System properties of the emulated device (Pixel 7, Android 14), consistent with AndroidFakes' Build fields. */
final class Props {
    static final Map<String, String> P = new HashMap<>();
    static {
        P.put("ro.product.model", "Pixel 7");
        P.put("ro.product.brand", "google");
        P.put("ro.product.manufacturer", "Google");
        P.put("ro.product.device", "panther");
        P.put("ro.product.name", "panther");
        P.put("ro.product.board", "panther");
        P.put("ro.hardware", "panther");
        P.put("ro.build.version.release", "14");
        P.put("ro.build.version.sdk", "34");
        P.put("ro.build.version.incremental", "11269751");
        P.put("ro.build.version.security_patch", "2024-02-05");
        P.put("ro.build.id", "UQ1A.240205.004");
        P.put("ro.build.display.id", "UQ1A.240205.004");
        P.put("ro.build.fingerprint", "google/panther/panther:14/UQ1A.240205.004/11269751:user/release-keys");
        P.put("ro.build.tags", "release-keys");
        P.put("ro.build.type", "user");
        P.put("ro.build.host", "abfarm-release-2004-0151");
        P.put("ro.build.user", "android-build");
        P.put("ro.build.date.utc", "1704200000");
        P.put("ro.bootloader", "cloudripper-1.0-11104286");
        P.put("ro.serialno", "");
        P.put("ro.debuggable", "0");
        P.put("ro.secure", "1");
        P.put("ro.boot.verifiedbootstate", "green");
        P.put("ro.boot.flash.locked", "1");
        P.put("ro.product.cpu.abi", "arm64-v8a");
        P.put("ro.product.cpu.abilist", "arm64-v8a");
        P.put("ro.board.platform", "gs201");
        P.put("persist.sys.timezone", "Asia/Shanghai");
        P.put("persist.sys.locale", "zh-CN");
        P.put("gsm.sim.state", "ABSENT");
        P.put("gsm.operator.numeric", "");
        P.put("init.svc.adbd", "stopped");
        P.put("sys.usb.state", "mtp");
        P.put("net.hostname", "");
        // PROPS="key=value,...": override / add properties (e.g. an emulator's bst.machine_id)
        for (String kv : System.getenv().getOrDefault("PROPS", "").split(",")) if (kv.contains("=")) P.put(kv.substring(0, kv.indexOf('=')), kv.substring(kv.indexOf('=') + 1));
    }
}
