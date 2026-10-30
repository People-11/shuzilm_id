package shuzilm.sample

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RadialGradient
import android.graphics.Shader
import android.media.MediaDrm
import android.net.ConnectivityManager
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.SystemClock
import android.telephony.TelephonyManager
import android.provider.Settings
import android.system.Os
import android.util.Base64
import org.json.JSONObject
import java.lang.reflect.Modifier
import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Calendar
import java.util.Locale
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.zip.Deflater
import kotlin.random.Random

// Pure-Kotlin replacement for shuzilm libdu.so v9.0.1 `query`: the mdna report that returns the device's DU id.
// Everything here was recovered from the Coolapk 16.6.4 build of libdu.so ("libdu sub_xxx" = function offsets in it).
//
// Value encodings (the modes of libdu's put helper sub_f07fc):
//   raw          the value as is
//   mode 2 / 3   DuCodec.enc (every char + 1, then shuffled)
//   mode 10      putTwin: enc of the value with one char dropped, and its checksum under "s" + key (as foO / sfOo)

object DuClient {

    private const val API_KEY = "<COOLAPK_APIKEY>" // Coolapk's key, passed to libdu at init (redacted in this copy)
    private const val PKG = "com.coolapk.market"
    private const val HOST_VERSION_NAME = "<HOST_VERSION_NAME>" // the host app version the report claims
    private const val HOST_VERSION_CODE = 0
    private const val LIBDU_MD5 = "97313e29420c51d0d8cc6e3a3586889a" // libdu sub_ea898 (ne8): MD5 of the loaded libdu.so
    // libdu sub_c8934 (zvW): the canvas text and background image
    private const val CANVAS_TEXT = "k\u956aR!\u0639\u062f\u062f.\u30c6" // escaped on purpose: the string mixes RTL Arabic, which editors reorder visually
    private const val CANVAS_PNG =
        "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAAJRJREFUeF7t14ENgCAMAEHYf9luAIE1/kwcQKt9bs/MWeXrvYDyvcoP/79+L8AvYAdYguU9YAmWpy+DzgEOQk6CKqACLMACLFDeAypQnj4LsAALsIAKqAALsAALlPeACpSnzwIswAIsoAIqwAIswALlPaAC5emzAAuwAAuogAqwAAuwQHkPqEB5+izAAizAAipQr8AFbLYDlUATJCcAAAAASUVORK5CYII="
    // libdu sub_b6e04 (6yY): the Widevine DRM scheme
    private val WIDEVINE = UUID.fromString("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed")

    // libdu sub_cb304 (52J): the lstat'ed paths
    private val STAT_PATHS = listOf(
        "/sdcard", "/system/lib", "/system/lib64", "/system/bin", "/sys/block",
        "/vendor/lib", "/dev/null", "/dev/block", "/storage/emulated/0", "/system/vendor"
    )

    // libdu sub_7dbec: emulator properties (BlueStacks, MuMu, MEmu, Droid4X, Nox, ...), each under its own key
    private val EMU_PROP_FIELDS = listOf(
        "i9d" to "bst.machine_id", "VUZ" to "nemud.player_uuid", "AJU" to "phone.mechineid",
        "fez" to "ro.microvirt.hmac", "OQE" to "ro.droid4x.host.mac", "ySX" to "bst.config.machineId",
        "GQd" to "persist.nox.device_id", "3Ky" to "sys.mac.address", "wv6" to "persist.nox.wifimac",
        "az6" to "redf.mathinecode", "67I" to "ro.boot.deviceid", "pc4" to "sys.usb.vserialno",
        "9WL" to "vmprop.androidid", "dga" to "vmprop.ip"
    )

    // libdu sub_51d44: vendor ad ids (OAIDs) the SDK's Java side keeps in <pkg>_prefs (key MD5(name), raw value;
    // native code only reads them), each sent mode 3; otime goes raw under za7
    private val VENDOR_ID_FIELDS = listOf(
        "fV5" to "asaid", "JCE" to "suaid", "CVi" to "mzaid", "dHR" to "nbaid", "vuS" to "gaid", "hJ7" to "hwaid",
        "B5W" to "hrid", "VcZ" to "laid", "CQH" to "voaid", "mZF" to "opaid", "mSa" to "sanl", "hpJ" to "xmid",
        "dTr" to "onepid", "oeH" to "mtid", "xsh" to "zteid", "IeP" to "fmid", "KjD" to "ssuid", "hiK" to "pzid",
        "K4N" to "cpid", "NZR" to "ebkd", "LhL" to "exoid"
    )

    // libdu sub_68f9c: stat times of these paths
    private val STAT_TIME_FIELDS = listOf(
        "aFw" to "/data/system", "Bos" to "/sdcard/Android/data/.nomedia", "IAI" to "/storage/emulated/0/DCIM",
        "IJK" to "/storage/emulated/0", "QNw" to "/sdcard/Android/data/com.google.android.gms", "ura" to "/storage/self/primary"
    )

    // libdu sub_dc988: MACs that mean "no real MAC"
    private val BAD_MACS = setOf("11:22:33:44:55:66", "00:00:00:00:00:00", "00:90:4c:11:22:33", "02:00:00:00:00:00", "ff:ff:ff:ff:ff:ff")

    // libdu sub_cd32c (nur): auto-clicker apps
    private val CLICKER_PACKAGES = listOf(
        "com.cygery.repetitouch.pro", "com.cyjh.mobileanjian", "com.touchsprite.android",
        "com.cjzs123.zhushou", "com.touchspriteent.android", "com.zidongdianji",
        "org.autojs.autojspro", "org.autojs.autojs", "com.zdanjian.zdanjian",
        "com.zdnewproject", "com.ifengwoo.zyjdkj", "com.angel.nrzs",
        "com.cyjh.mobileanjian.vip", "com.shumai.shudaxia", "fun.tooling.clicker.cn",
        "com.dianjiqi", "com.miaodong.autoactionssss", "com.mxz.wxautojiafujinderen",
        "com.touchelf.app", "com.stardust.scriptdroid", "com.adinall.autoclick",
        "com.i_cool.auto_clicker", "com.kongshan.aidianji", "com.xptech.catclicker",
        "com.tingniu.autoclick", "com.yicu.yichujifa", "com.smallyin.autoclick",
        "com.ksxkq.autoclick", "com.x2.clicker", "com.scott.autoclickhelper",
        "com.auyou.auyouwzs"
    )

    // libdu sub_cd8ac (tth): root manager apps
    private val ROOT_PACKAGES = listOf(
        "eu.chainfire.supersu", "com.noshufou.android.su", "com.noshufou.android.su.elite",
        "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su",
        "com.fox2code.mmm", "io.github.vvb2060.magisk", "com.kingroot.kinguser",
        "com.kingo.root", "com.smedialink.oneclickroot", "com.zhiqupk.root.global",
        "com.alephzain.framaroot", "me.weishu.kernelsu"
    )

    // libdu sub_ce2e4 (LAh): hook / virtual-app frameworks, one digit per group
    private val HOOK_GROUPS = listOf(
        listOf("org.lsposed.manager", "org.lsposed.lspatchs"),
        listOf("io.va.exposed", "io.va.exposed64", "io.virtualapp.sandvxposed64"),
        listOf("de.robv.android.xposed.installer", "org.meowcat.edxposed.manager"),
        listOf("com.saurik.substrate", "top.canyie.dreamland.manager"),
        listOf("moe.shizuku.privileged.api"),
        listOf("com.tsng.hidemyapplist", "com.tsng.hidemyroot"),
        listOf("com.topjohnwu.magisk", "io.github.huskydg.magisk"),
        listOf("me.weishu.exp", "com.soft.apk008v", "com.yztc.studio.plugin", "com.uwish.app")
    )

    // libdu sub_c36e8 (QgA): su binaries
    private val SU_PATHS = listOf(
        "/system/app/SuperUser/SuperUser.apk", "/system/sd/xbin/su",
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/su"
    )

    // libdu sub_d8e1c (5mZ): TLS methods that turn native when hooked, one bit each
    private val SSL_METHODS = listOf(
        "com.android.org.conscrypt.TrustManagerImpl" to "checkServerTrusted",
        "com.android.org.conscrypt.TrustManagerImpl" to "checkTrusted",
        "com.android.org.conscrypt.TrustManagerImpl" to "checkTrustedRecursive",
        "com.android.org.conscrypt.TrustManagerImpl" to "verifyChain",
        "javax.net.ssl.SSLContext" to "init",
        "javax.net.ssl.TrustManagerFactory" to "getTrustManagers",
        "javax.net.ssl.HttpsURLConnection" to "setDefaultHostnameVerifier",
        "android.security.net.config.NetworkSecurityTrustManager" to "checkPins",
        "com.android.org.conscrypt.OpenSSLSocketImpl" to "verifyCertificateChain",
        "com.android.org.conscrypt.ConscryptFileDescriptorSocket" to "verifyCertificateChain",
        "com.android.org.conscrypt.CertPinManager" to "isChainValid"
    )

    // libdu sub_d9ca0 (D32): camera methods that turn native when hooked (a virtual camera), one bit each
    private val CAMERA_METHODS = listOf(
        "android.hardware.Camera" to "setPreviewCallback",
        "android.hardware.Camera" to "setPreviewCallbackWithBuffer",
        "android.hardware.Camera" to "startPreview",
        "android.hardware.camera2.impl.CameraDeviceImpl" to "createCaptureSession",
        "android.media.ImageReader" to "newInstance"
    )

    // libdu sub_145984 has auni.telecome.cn; some ad-block lists drop it, so both report hosts are asked
    // and the first id back wins
    private val HOSTS = listOf("https://auni.telecome.cn", "https://global-auni.checktrustworthiness.com")

    // Blocking network call. Returns the DU... id, or null when the server refuses (all-zero id) or anything fails.
    fun query(context: Context, previousId: String? = null): String? = runCatching {
        val payload = buildPayload(context.applicationContext, previousId).toString()
        // p: libdu sub_143950, MD5 of the package name + "." + a key hardcoded (encrypted) in the .so;
        // h: "0" on a first report, libdu sends MD5(n_a + ".889e0b01") once it has an id
        val path = "/a/mdna/report?v=8.7&t=m&p=${DuCodec.md5Upper("$PKG.37be8a1ee106979a")}" +
                "&r=${UUID.randomUUID().toString().replace("-", "")}&n=0&l=2&h=0"
        val body = DuCodec.xor(deflate(payload.toByteArray()))
        val pool = Executors.newFixedThreadPool(HOSTS.size)
        try {
            // invokeAny: the first task that returns without throwing; the other is cancelled
            pool.invokeAny(HOSTS.map { host -> Callable { report(host + path, body) ?: error("no id from $host") } })
        } finally {
            pool.shutdownNow()
        }
    }.getOrNull()

    // One POST. The reply is XOR'd JSON: err, the id (n_a, else cdd), and more the SDK would keep (see buildPayload's end)
    private fun report(url: String, body: ByteArray): String? {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 30000
            readTimeout = 30000
            doOutput = true
            setRequestProperty("Content-Length", body.size.toString())
        }
        try {
            conn.outputStream.use { it.write(body) }
            if (conn.responseCode != 200) return null
            val reply = JSONObject(String(DuCodec.xor(conn.inputStream.use { it.readBytes() })))
            if (reply.optString("err") != "0") return null
            return reply.optString("n_a").ifEmpty { reply.optString("cdd") }.takeIf { it.isNotEmpty() && !it.all { c -> c == '0' } }
        } finally {
            conn.disconnect()
        }
    }

    private fun deflate(data: ByteArray): ByteArray {
        val d = Deflater() // zlib framing, same as libz compress()
        d.setInput(data)
        d.finish()
        val out = ByteArrayOutputStream()
        val buf = ByteArray(4096)
        while (!d.finished()) out.write(buf, 0, d.deflate(buf))
        d.end()
        return out.toByteArray()
    }

    // libdu sub_68f9c and the builders it calls. What is sent is the minimum the server answers with an id; every
    // other field libdu sends is below, commented out, with the safe value of each check.
    @SuppressLint("HardwareIds")
    @Suppress("UNUSED_VARIABLE") // t0, pkgInfo, net and tm feed the commented-out fields
    private fun buildPayload(ctx: Context, previousId: String?): JSONObject {
        val t0 = SystemClock.elapsedRealtime()
        val androidId = Settings.Secure.getString(ctx.contentResolver, Settings.Secure.ANDROID_ID).orEmpty()
        val pkgInfo = ctx.packageManager.getPackageInfo(ctx.packageName, 0)
        val nowMs = System.currentTimeMillis()
        val (sec, ms) = nowMs / 1000 to nowMs % 1000
        val net = networkCaps(ctx)
        val tm = ctx.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
        val sha1 = DuCodec.hashHexUpper("SHA-1", androidId)
        return JSONObject().apply {
            // identity (the server links devices mainly on these)
            put("foO", DuCodec.enc(DuCodec.dropChar(androidId))) // ANDROID_ID, mode 10 with sfOo
            put("sfOo", DuCodec.checksum(androidId))
            put("P1J", DuCodec.fakeMac(sha1)) // libdu's stand-in MAC from SHA-1(ANDROID_ID); later reports send the reply's o_a
            put("AYk", DuCodec.fakeMac(sha1))
            widevineId()?.let { put("6yY", it) }
            previousId?.let { put("ubF", it) } // the last id (libdu pref n_a)
            put("dLH", DuCodec.enc(bootUuid(ctx))) // libdu pref boot_uuid: random, once per install (mIS is the kernel's boot_id)

            // SDK and protocol; without 3mS / AAA / BBB the server answers empty
            put("75c", API_KEY)
            put("DUv", PKG)
            put("3mS", "v9.0.1")
            put("AAA", "v1.0")
            put("BBB", "v1.0")
            put("UOv", DuCodec.enc(bootTime()))
            put("2cO", "%d.%03d000000".format(sec, ms)) // the report's time

            // device
            put("R37", Build.MANUFACTURER)
            put("R3d", Build.MODEL)
            put("R41", Build.VERSION.RELEASE)
            put("SAN", Build.VERSION.SDK_INT)

            // ---- the rest of libdu's mdna payload, not sent ----

            // system properties and settings
            // put("R53", prop("ro.debuggable", "0"))
            // put("R63", prop("init.svc.adbd", "stopped"))
            // put("Ra", prop("gsm.sim.state", "").substringBefore(','))
            // prop("gsm.operator.numeric", "").takeIf { it.isNotEmpty() }?.let { put("R5a", it) }
            // prop("net.hostname", "").takeIf { it.isNotEmpty() }?.let { put("R1e", DuCodec.enc(it)) }
            // put("S6e", readFirstLine("/sys/fs/selinux/enforce")?.toIntOrNull() ?: 1)
            // put("fPV", "${Locale.getDefault().country},${Locale.getDefault().language}")
            // put("h6Z", "酷安") // getApplicationLabel; a reimplementation would give its own name away

            // files and fingerprints
            // put("ibF", DuCodec.enc(statfsId()))
            // put("52J", DuCodec.enc(STAT_PATHS.joinToString(",") { lstatId(it) }))
            // put("YWu", hosts())
            // fontsListMd5()?.let { put("w91", it) }
            // systemLibMd5()?.let { put("gEd", it) }
            // fileMd5("/system/lib64/libcutils.so")?.let { put("5Tv", DuCodec.enc(it)) }
            // readFirstLine("/proc/sys/kernel/random/boot_id")?.let { put("mIS", DuCodec.enc(it)) }
            // readFirstLine("/sys/block/mmcblk0/device/serial")?.let { put("p1m", DuCodec.enc(it)) } // eMMC serial, unreadable on most phones
            // readFirstLine("/sys/devices/soc0/serial_number")?.let { put("GZY", DuCodec.enc(it)) } // SoC serial
            // readPrefix("/sys/block/mmcblk0/device/cid", 32)?.let { put("dJs", DuCodec.enc(it)) } // eMMC CID
            // STAT_TIME_FIELDS.forEach { (key, path) -> statTimes(path)?.let { put(key, DuCodec.enc(it)) } }
            // statTimes("/data/data/${ctx.packageName}/shared_prefs", mtime = false)?.let { put("KyU", DuCodec.enc(it)) }
            // canvasMd5()?.let { put("zvW", DuCodec.enc(it)) }
            // put("G8U", memAndStorage())
            // put("K5f", DuCodec.md5Upper("%d.%03d000000".format(sec, ms) + android.os.Process.myPid() + Random.nextInt(Int.MAX_VALUE) + android.os.Process.myTid())) // per-report id (libdu sub_6716c)

            // network
            // put("iYB", (activeLinkInfo(ctx, withProxy = true) ?: JSONObject()).apply { // libdu sub_b3fe0
            //     put("AWo", DuCodec.enc(listOf(10, 9, 8, 6, 5, 4, 3, 2, 1, 0).joinToString("") { if (net?.hasTransport(it) == true) "1" else "0" }))
            //     Regex("""\[ Transports: (\S+) Capabilities:""").find(net.toString())?.let { put("mch", DuCodec.enc(it.groupValues[1])) }
            //     put("8tS", net?.linkDownstreamBandwidthKbps ?: 0)
            //     put("Hsz", net?.linkUpstreamBandwidthKbps ?: 0)
            // })
            // put("7S2", allLinkInfo(ctx)) // libdu sub_b3b6c: {"0": {txo, Zne, MCN}, ...} for getAllNetworks()
            // dhcpIp(ctx)?.let { put("wSK", it) }
            // activeNetworkInfo(ctx)?.let { ni -> put("zpA", ni.typeName); ni.subtypeName?.takeIf { it.isNotEmpty() }?.let { put("ozK", it) } }
            // put("J7w", mobileDataEnabled(ctx, tm))

            // hardware and telephony ids, mostly unreadable to apps on recent Android (P1J / AYk stand in for the MACs)
            // putTwin("41j", wlanMac()); putTwin("nyx", ipLinkMac("wlan1")); putTwin("M96", ipLinkMac("p2p0"))
            // putTwin("fM0", factoryMac())
            // imei(tm)?.let { putTwin("p92", it) } // READ_PHONE_STATE, refused to apps from Android 10
            // if (Build.VERSION.SDK_INT >= 26) runCatching { tm?.imei }.getOrNull()?.let { putTwin("3J5", it) } // same gate
            // dataNetworkType(tm)?.let { put("LkB", it) } // READ_PHONE_STATE
            // put("JPd", tm?.simOperator?.takeIf { it.isNotEmpty() } ?: "0")
            // put("bf7", tm?.networkOperator?.takeIf { it.isNotEmpty() } ?: "0")
            // put("4VP", tm?.simState ?: 0)
            // settingsString(ctx, "oaid")?.let { put("IOe", DuCodec.enc(it)) }
            // settingsGlobal(ctx, "pps_oaid")?.let { put("q6I", DuCodec.enc(it)) } // Huawei
            // VENDOR_ID_FIELDS: a reimplementation has no Java side collecting them

            // environment checks, with the safe value of each
            // settingsGlobal(ctx, "adb_enabled")?.let { put("c2O", it) } // "0"
            // settingsGlobal(ctx, "stay_on_while_plugged_in")?.let { put("PV8", it) } // "0"
            // put("LAh", checkHookStatus(ctx)) // "11111111"
            // put("90P", checkMounts(ctx)) // "11"
            // put("bzt", checkTelephonyHook()) // "0000"
            // put("Xl9", checkMaps()) // "0000"
            // put("qH9", checkDataDir(ctx)) // "0"
            // put("wlM", usbState(ctx)) // 0
            // put("QVn", permissionMask(ctx)) // 0
            // put("nur", if (hasAnyPackage(ctx, CLICKER_PACKAGES)) 1 else 0) // 0
            // put("tth", if (hasAnyPackage(ctx, ROOT_PACKAGES)) 1 else 0) // 0
            // put("QgA", checkSu()) // 0
            // put("Chh", if (runCatching { File("/storage/emulated/0/Android/data").canRead() }.getOrDefault(false)) 1 else 0) // 0
            // put("D32", checkCameraHook()) // 0
            // put("0KQ", checkTrustManager()) // 0
            // put("5mZ", checkSslHook()) // 0
            // put("ZZA", if (listOf("tun0", "ppp0", "tap0").any { File("/sys/class/net/$it").exists() }) 1 else 0) // a VPN is up; 0
            // tracerPid()?.let { put("iZS", it) } // 0
            // accessibilityServices(ctx)?.let { put("yzW", DuCodec.enc(it)) } // not sent (none enabled)
            // userCaCerts()?.let { put("Q23", it) } // not sent (no user-installed CA)
            // EMU_PROP_FIELDS.forEach { (key, p) -> prop(p, "").takeIf { it.isNotEmpty() }?.let { put(key, DuCodec.enc(it)) } } // not sent

            // app and SDK constants
            // put("EV2", HOST_VERSION_NAME)
            // put("Zrs", HOST_VERSION_CODE)
            // put("h8h", if (Build.VERSION.SDK_INT >= 28) pkgInfo.longVersionCode else @Suppress("DEPRECATION") pkgInfo.versionCode.toLong())
            // put("Qg1", pkgInfo.firstInstallTime)
            // put("LMi", pkgInfo.lastUpdateTime)
            // put("GVp", "DefaultChannel")
            // put("ne8", LIBDU_MD5)
            // put("msg", JSONObject().put("custom", "")) // the host's custom JSON; Coolapk passes {"custom":""}
            // put("fxb", timingMetric())
            // put("Db2", 2)
            // put("cHo", 0)
            // put("B3k", SystemClock.elapsedRealtime() - t0) // ms spent building the payload

            // Also in libdu's payload, but from state its own earlier reports leave, so never in a first report
            // (checked in the harness with a faked reply and a second query):
            //   dGh   pref ndcd: the ANDROID_ID of the first report (mode 3)
            //   kWV   pref mtr: the last report's "K5f,transport,fallback used,ms to fallback,ms total" (mode 2)
            //   wHp   pref aid / cache file e2dfcfaa: the reply's aid
            //   nAt   pref nctl, else cache file eae6ff4a
            //   w5v   pref pkcg, written by a later report: 0 / 1 / 2 = our package found in
            //         getPackagesHoldingPermissions(INTERNET) with matching / different install times / not listed
            //   2mV   the reply's dlab, kept in <pkg>_dna device_label, AES/ECB-decrypted with MD5("<pkg>.54bc01a66a")[:16]
            //   v1X   /sdcard/.o_a, which any app's SDK writes by shell echo once a reply carries o_a: a cross-app id
            //   3k9, 8N4  1 and the kept id (pref n_a, else cache file e2308fa0) when pref fut, the firstInstallTime
            //         recorded on the SDK's first run, no longer matches: prefs restored into a fresh install
            //   My2   config partnerCode (Coolapk passes none)
        }
    }

    // libdu sub_b6e04 (6yY): the Widevine DRM device id, hex
    private fun widevineId(): String? = runCatching {
        val drm = MediaDrm(WIDEVINE)
        try {
            drm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID).joinToString("") { "%02x".format(it) }
        } finally {
            if (Build.VERSION.SDK_INT >= 28) drm.close() else @Suppress("DEPRECATION") drm.release()
        }
    }.getOrNull()

    // libdu sub_c70f8 (UOv): when the device booted, CLOCK_REALTIME - CLOCK_BOOTTIME as "%ld.%ld" (nanoseconds
    // not zero-padded)
    private fun bootTime(): String {
        val ns = System.currentTimeMillis() * 1_000_000 - SystemClock.elapsedRealtimeNanos()
        return "${ns / 1_000_000_000}.${ns % 1_000_000_000}"
    }

    // libdu sub_b19b4 (G8U): MYA = "MemTotal,MemFree" in kB (looked for in /proc/meminfo's first 5 lines),
    // H4S = "%f,%f" of /data's total and available GiB
    private fun memAndStorage(): JSONObject = JSONObject().apply {
        runCatching {
            val lines = File("/proc/meminfo").bufferedReader().useLines { it.take(5).toList() }
            fun kb(line: String, name: String) = Regex("""^$name: *(\d+) kB""").find(line)?.groupValues?.get(1)
            val i = lines.indexOfFirst { kb(it, "MemTotal") != null }
            if (i >= 0) {
                val free = lines.drop(i + 1).firstNotNullOfOrNull { kb(it, "MemFree") }
                put("MYA", DuCodec.enc(kb(lines[i], "MemTotal") + (free?.let { ",$it" } ?: "")))
            }
        }
        runCatching {
            val st = android.os.StatFs(android.os.Environment.getDataDirectory().path)
            val gib = (1L shl 30).toDouble()
            put("H4S", DuCodec.enc("%f,%f".format(Locale.US, st.blockCountLong * st.blockSizeLong / gib, st.availableBlocksLong * st.blockSizeLong / gib)))
        }
    }

    // libdu sub_c003c (ibF): "%x%x-%ld-%ld" of statfs("/"): f_fsid[0], f_fsid[1], f_blocks, f_files
    private fun statfsId(): String = runCatching {
        val st = Os.statvfs("/")
        // bionic packs the two fsid words as val[0] | val[1] << 32
        "%x%x-%d-%d".format(st.f_fsid and 0xffffffffL, st.f_fsid ushr 32, st.f_blocks, st.f_files)
    }.getOrDefault("")

    // libdu sub_cb304 (52J), per path: "%llu:%llu" of lstat st_ino, st_dev; "0:0" when lstat fails
    private fun lstatId(path: String): String = runCatching {
        val st = Os.lstat(path)
        "${st.st_ino.toULong()}:${st.st_dev.toULong()}"
    }.getOrDefault("0:0")

    // libdu sub_133048 (dLH): a random UUID kept in a pref (libdu's boot_uuid, ours in du_client)
    private fun bootUuid(ctx: Context): String = ctx.getSharedPreferences("du_client", Context.MODE_PRIVATE).let { sp ->
        sp.getString("boot_uuid", null) ?: UUID.randomUUID().toString().also { sp.edit().putString("boot_uuid", it).apply() }
    }

    // mode 10 of libdu's put (sub_f07fc), as foO / sfOo: the value with a char dropped, and "s" + key its checksum
    private fun JSONObject.putTwin(key: String, value: String?) {
        if (value.isNullOrEmpty()) return
        put(key, DuCodec.enc(DuCodec.dropChar(value)))
        put("s$key", DuCodec.checksum(value))
    }

    // lower-case MD5 of a file's bytes (generic)
    private fun fileMd5(path: String): String? = runCatching { File(path).readBytes() }.getOrNull()
        ?.let { b -> MessageDigest.getInstance("MD5").digest(b).joinToString("") { "%02x".format(it) } }

    // libdu sub_eee20: the file's first bytes as they are
    private fun readPrefix(path: String, n: Int): String? = runCatching {
        File(path).inputStream().use { val b = ByteArray(n); String(b, 0, maxOf(it.read(b), 0)) }
    }.getOrNull()?.takeIf { it.isNotEmpty() }

    // libdu sub_bdca4 & co: "atime.nsec,mtime.nsec" ("%ld.%ld,%ld.%ld"), only when atime is set; KyU has atime alone
    private fun statTimes(path: String, mtime: Boolean = true): String? = runCatching {
        val st = Os.stat(path)
        val (a, m) = if (Build.VERSION.SDK_INT >= 27) "${st.st_atim.tv_sec}.${st.st_atim.tv_nsec}" to "${st.st_mtim.tv_sec}.${st.st_mtim.tv_nsec}"
        else "${st.st_atime}.0" to "${st.st_mtime}.0"
        if (a.startsWith("0.")) null else if (mtime) "$a,$m" else a
    }.getOrNull()

    // libdu sub_c8934 (zvW): CANVAS_PNG as RGB_565, a radial gradient (red to blue) over it, then CANVAS_TEXT;
    // the non-zero pixel bytes (zeros skipped, at most 0xffe) MD5'd, lower case, when there are at least 8. libdu calls
    // Paint.setTextSize(int), which doesn't exist, so the text keeps the default size
    private fun canvasMd5(): String? = runCatching {
        val png = Base64.decode(CANVAS_PNG, Base64.DEFAULT)
        val bmp = BitmapFactory.decodeByteArray(png, 0, png.size).copy(Bitmap.Config.RGB_565, true)
        val (w, h) = bmp.width to bmp.height
        Canvas(bmp).apply {
            drawRect(1f, 1f, w - 1f, h - 1f, Paint().apply {
                shader = RadialGradient(w / 3f, h / 3f, w / 3f, 0xFFFF0000.toInt(), 0xFF0000FF.toInt(), Shader.TileMode.CLAMP)
            })
            drawText(CANVAS_TEXT, 1f, 10f, Paint().apply {
                color = 0xFFCCCCCC.toInt()
                style = Paint.Style.FILL_AND_STROKE
                textAlign = Paint.Align.LEFT
            })
        }
        val buf = ByteBuffer.allocate(bmp.byteCount)
        bmp.copyPixelsToBuffer(buf)
        val bytes = buf.array().filter { it != 0.toByte() }.take(0xffe).toByteArray()
        if (bytes.size < 8) null else MessageDigest.getInstance("MD5").digest(bytes).joinToString("") { "%02x".format(it) }
    }.getOrNull()

    // libdu sub_af5dc: Settings.Global.getString
    private fun settingsGlobal(ctx: Context, key: String): String? =
        runCatching { Settings.Global.getString(ctx.contentResolver, key) }.getOrNull()

    // libdu sub_af71c: Settings.Secure, then Settings.Global
    private fun settingsString(ctx: Context, key: String): String? =
        runCatching { Settings.Secure.getString(ctx.contentResolver, key) }.getOrNull() ?: settingsGlobal(ctx, key)

    // libdu sub_b275c (wSK): the Wi-Fi DHCP address, dotted
    @Suppress("DEPRECATION")
    private fun dhcpIp(ctx: Context): String? = runCatching {
        val ip = (ctx.applicationContext.getSystemService(Context.WIFI_SERVICE) as android.net.wifi.WifiManager).dhcpInfo.ipAddress
        if (ip == 0) null else "${ip and 0xff}.${ip shr 8 and 0xff}.${ip shr 16 and 0xff}.${ip shr 24 and 0xff}"
    }.getOrNull()

    // libdu sub_b5c5c / sub_b5f4c (zpA / ozK): the active network's type and subtype names
    @Suppress("DEPRECATION")
    private fun activeNetworkInfo(ctx: Context) =
        runCatching { (ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).activeNetworkInfo }.getOrNull()

    // libdu sub_a6374 (LkB): TelephonyManager.getDataNetworkType, when >= 0
    @SuppressLint("MissingPermission")
    private fun dataNetworkType(tm: TelephonyManager?): Int? =
        runCatching { if (Build.VERSION.SDK_INT >= 24) tm?.dataNetworkType else null }.getOrNull()?.takeIf { it >= 0 }

    // libdu sub_a535c (p92): getDeviceId, else getImei
    @SuppressLint("MissingPermission", "HardwareIds")
    @Suppress("DEPRECATION")
    private fun imei(tm: TelephonyManager?): String? = runCatching { tm?.deviceId ?: if (Build.VERSION.SDK_INT >= 26) tm?.imei else null }.getOrNull()

    // libdu sub_c20b4 / sub_4adb4 (via factoryMac): wlan0 (or eth0) from sysfs, else from `ip link`;
    // placeholder MACs don't count
    private fun wlanMac(): String? = listOf("/sys/class/net/wlan0/address", "/sys/class/net/eth0/address")
        .firstNotNullOfOrNull { readFirstLine(it) }?.takeIf { it !in BAD_MACS } ?: ipLinkMac("wlan0")

    // libdu sub_c21d8: `ip link`, "link/ether" of the named interface (wlan0, wlan1, p2p0)
    private fun ipLinkMac(iface: String): String? = runCatching {
        val out = Runtime.getRuntime().exec(arrayOf("ip", "link")).inputStream.bufferedReader().readLines()
        val i = out.indexOfFirst { Regex("^\\d+: $iface[:@]").containsMatchIn(it) }
        out.getOrNull(i + 1)?.let { Regex("link/ether ([0-9a-f:]{17})").find(it)?.groupValues?.get(1) }
    }.getOrNull()?.takeIf { it !in BAD_MACS }

    // libdu sub_4afb4: wlan0's MAC, unless Android 9+ gives a missing or locally administered (randomised: 2nd digit
    // 2/6/a/e) one; then the factory address guessed from wlan1 / p2p0, which drivers derive from it
    private fun factoryMac(): String? {
        val w0 = wlanMac()
        fun bad(m: String?) = m == null || m.getOrElse(1) { ' ' } in "26ae"
        if (Build.VERSION.SDK_INT < 28 || !bad(w0)) return w0
        val w1 = ipLinkMac("wlan1")
        val p2p = ipLinkMac("p2p0")
        if (w1 != null && p2p != null && w1.length == p2p.length && w1.length <= 18 &&
            (w1.length < 5 || w1.substring(2, w1.length - 2) == p2p.substring(2, p2p.length - 2))
        ) return if (w1.length >= 16) w1.take(15) + p2p.drop(15) else null
        if (w1 != null && !bad(w1)) {
            val (prev, last) = w1[w1.length - 2] to w1.last()
            return w1.dropLast(2) + when (last) {
                'a', 'A' -> "${prev}9"
                '0' -> "${if (prev == '0') prev else prev - 1}f"
                else -> "$prev${last - 1}"
            }
        }
        return p2p?.replaceRange(1, 2, "2") ?: w0
    }

    // libdu sub_b374c: a network's interface name (txo), addresses (Zne), DNS servers (MCN), all as List.toString(),
    // and for the active one its HTTP proxy host (9X9, raw) and port (dki)
    private fun linkInfo(lp: android.net.LinkProperties, withProxy: Boolean) = JSONObject().apply {
        lp.interfaceName?.let { put("txo", DuCodec.enc(it)) }
        if (withProxy) lp.httpProxy?.let { p -> p.host?.let { put("9X9", it) }; if (p.port >= 1) put("dki", p.port) }
        put("Zne", DuCodec.enc(lp.linkAddresses.toString()))
        put("MCN", DuCodec.enc(lp.dnsServers.toString()))
    }

    // libdu sub_b3fe0 (iYB): linkInfo of the active network
    private fun activeLinkInfo(ctx: Context, withProxy: Boolean): JSONObject? = runCatching {
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        cm.getLinkProperties(cm.activeNetwork)?.let { linkInfo(it, withProxy) }
    }.getOrNull()

    // libdu sub_b3b6c (7S2): linkInfo of every network, keyed by index
    private fun allLinkInfo(ctx: Context): JSONObject? = runCatching {
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        JSONObject().apply { cm.allNetworks.forEachIndexed { i, n -> cm.getLinkProperties(n)?.let { put("$i", linkInfo(it, false)) } } }
    }.getOrNull()

    // libdu sub_c82e0 (iZS): TracerPid from /proc/self/status
    private fun tracerPid(): Int? = runCatching {
        File("/proc/self/status").readLines().firstOrNull { it.startsWith("TracerPid:") }?.substringAfter(':')?.trim()?.toInt()
    }.getOrNull()

    // libdu sub_976a0 (yzW): enabled accessibility services' packages, each followed by ','
    private fun accessibilityServices(ctx: Context): String? = runCatching {
        val am = ctx.getSystemService(Context.ACCESSIBILITY_SERVICE) as android.view.accessibility.AccessibilityManager
        am.getEnabledAccessibilityServiceList(-1).joinToString("") { it.id.substringBefore('/') + "," }
    }.getOrNull()?.takeIf { it.isNotEmpty() }

    // libdu sub_d7dd4 (Q23): user-installed CAs ("user:" aliases of AndroidCAStore) as "alias+issuer;",
    // up to 1023 chars
    private fun userCaCerts(): String? = runCatching {
        val ks = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
        val sb = StringBuilder()
        for (alias in ks.aliases()) {
            if (!alias.startsWith("user:")) continue
            val issuer = (ks.getCertificate(alias) as? X509Certificate)?.issuerDN?.name.orEmpty()
            if (sb.length + alias.length + issuer.length + 2 <= 0x3ff) sb.append(alias).append('+').append(issuer).append(';')
        }
        sb.toString()
    }.getOrNull()?.takeIf { it.isNotEmpty() }


    // libdu sub_d82f4 (YWu): "%s+%s;" of ip and first host per non-'#' line, capped at 511 chars
    // (ad-block hosts files are MBs).
    private fun hosts(): String = runCatching {
        val lines = listOf("/system/etc/hosts", "/etc/hosts").firstNotNullOf { runCatching { File(it).readLines() }.getOrNull() }
        val sb = StringBuilder()
        for (line in lines) {
            if (line.isEmpty() || line[0] == '#') continue
            val t = line.trim().split(Regex("\\s+"))
            if (t.size < 2) continue
            val ip = t[0].take(63)
            val host = t[1].take(255)
            if (sb.length + ip.length + host.length + 2 <= 0x1ff) sb.append(ip).append('+').append(host).append(';')
        }
        sb.toString()
    }.getOrDefault("")

    // libdu sub_bba60 / sub_bbaa0 (w91): /system/fonts' names in readdir order, no separator, skipping names that start
    // with '.', while the total stays under 4096 chars; then MD5 (upper, as p). Not sent when the dir can't be read.
    private fun fontsListMd5(): String? {
        val names = File("/system/fonts").list() ?: return null
        val sb = StringBuilder()
        for (name in names) {
            if (name.startsWith(".")) continue
            if (sb.length + name.length >= 0x1000) break
            sb.append(name)
        }
        return DuCodec.md5Upper(sb.toString())
    }

    // libdu sub_bc530 / sub_e2400 (gEd): lower-case MD5 of libreference-ril.so's bytes, else libc.so's (32-bit libs,
    // so 64-bit-only phones send neither)
    private fun systemLibMd5(): String? = listOf("/system/lib/libreference-ril.so", "/system/lib/libc.so")
        .firstNotNullOfOrNull { path -> runCatching { File(path).readBytes() }.getOrNull() }
        ?.let { bytes -> MessageDigest.getInstance("MD5").digest(bytes).joinToString("") { "%02x".format(it) } }

    // libdu sub_b3fe0 (iYB): the active network's capabilities
    private fun networkCaps(ctx: Context) = runCatching {
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        cm.getNetworkCapabilities(cm.activeNetwork)
    }.getOrNull()

    // libdu sub_6869c (fxb): 100000 + local hour * 20 + rand() % 10, nudged by 1 depending on parity
    private fun timingMetric(): Int {
        val r = Random.nextInt(10)
        val base = 100000 + Calendar.getInstance().get(Calendar.HOUR_OF_DAY) * 20 + r
        return if (r % 2 == 0) base - 1 else base + 1
    }

    // libdu sub_9200c (QVn): one bit per granted permission, in this order
    private fun permissionMask(ctx: Context): Int {
        val pm = ctx.packageManager
        val pkg = ctx.packageName
        val perms = listOf(
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.NEARBY_WIFI_DEVICES",
            "android.permission.READ_PHONE_STATE",
            "android.permission.BLUETOOTH_SCAN",
            "android.permission.READ_EXTERNAL_STORAGE"
        )
        var mask = 0
        for (i in perms.indices) {
            if (pm.checkPermission(perms[i], pkg) == PackageManager.PERMISSION_GRANTED) mask = mask or (1 shl i)
        }
        return mask
    }

    // libdu sub_b6220 (J7w): mobile data switched on
    private fun mobileDataEnabled(ctx: Context, tm: TelephonyManager?): Int {
        return runCatching {
            if (Build.VERSION.SDK_INT >= 26) {
                if (tm?.isDataEnabled == true) 1 else 0
            } else {
                val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                if (cm?.javaClass?.getMethod("getMobileDataEnabled")?.invoke(cm) == true) 1 else 0
            }
        }.getOrDefault(0)
    }

    // libdu sub_cec88 (wlM): the sticky USB_STATE broadcast, 2 = connected, 1 = adb
    private fun usbState(ctx: Context): Int {
        return runCatching {
            val usb = ctx.registerReceiver(null, IntentFilter("android.hardware.usb.action.USB_STATE"))
            var state = 0
            if (usb?.getBooleanExtra("connected", false) == true) state = state or 2
            if (usb?.getBooleanExtra("adb", false) == true) state = state or 1
            state
        }.getOrDefault(0)
    }

    // libdu sub_cd32c / sub_cd8ac (nur / tth): any of the packages installed
    private fun hasAnyPackage(ctx: Context, pkgs: List<String>): Boolean {
        val pm = ctx.packageManager
        return pkgs.any { runCatching { pm.getPackageInfo(it, 0) }.isSuccess }
    }

    // libdu sub_ce2e4 (LAh): per HOOK_GROUPS group, '0' when one of its packages is installed
    private fun checkHookStatus(ctx: Context): String {
        val pm = ctx.packageManager
        return HOOK_GROUPS.map { g -> if (g.any { runCatching { pm.getPackageInfo(it, 0) }.isSuccess }) '0' else '1' }.joinToString("")
    }

    // libdu sub_cfcfc (90P): '0' for a magisk mount, then '0' for an unreadable APK
    private fun checkMounts(ctx: Context): String {
        val hasMagisk = runCatching {
            listOf("/proc/self/mountinfo", "/proc/mounts").firstNotNullOf { runCatching { File(it).readLines() }.getOrNull() }
                .any { it.contains("magisk", true) }
        }.getOrDefault(false)
        val apkOk = runCatching { File(ctx.applicationInfo.publicSourceDir).length() > 0 }.getOrDefault(true)
        return "${if (hasMagisk) '0' else '1'}${if (apkOk) '1' else '0'}"
    }

    // libdu sub_d9980 (Xl9): "0001" when /proc/self/maps names xposed or frida
    private fun checkMaps(): String {
        return runCatching {
            val hasHook = File("/proc/self/maps").bufferedReader().useLines { lines ->
                lines.any { it.contains("xposed", true) || it.contains("frida", true) }
            }
            if (hasHook) "0001" else "0000"
        }.getOrDefault("0000")
    }

    // libdu sub_972a0 (qH9): "1" when the parent of our data dir can be listed (only outside the normal app sandbox)
    private fun checkDataDir(ctx: Context): String {
        return runCatching {
            val parent = File(ctx.applicationInfo.dataDir).parentFile
            if (parent?.canRead() == true && !parent.listFiles().isNullOrEmpty()) "1" else "0"
        }.getOrDefault("0")
    }

    // libdu sub_c36e8 (QgA): a su binary exists
    private fun checkSu(): Int {
        return if (SU_PATHS.any { File(it).exists() }) 1 else 0
    }

    // libdu sub_d8e1c (5mZ): SSL_METHODS bits set for methods that are native (hooked)
    private fun checkSslHook(): Int {
        var mask = 0
        for ((i, pair) in SSL_METHODS.withIndex()) {
            runCatching {
                val cls = Class.forName(pair.first)
                if (cls.declaredMethods.any { it.name == pair.second && Modifier.isNative(it.modifiers) }) {
                    mask = mask or (1 shl i)
                }
            }
        }
        return mask
    }

    // libdu sub_d90e4 (0KQ): 1 when the default trust manager accepts an empty chain (a TLS bypass is installed)
    private fun checkTrustManager(): Int {
        return runCatching {
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(null as KeyStore?)
            for (tm in tmf.trustManagers) {
                if (tm is X509TrustManager) {
                    try {
                        tm.checkServerTrusted(emptyArray<X509Certificate>(), "RSA")
                        return 1
                    } catch (_: Throwable) {
                    }
                }
            }
            0
        }.getOrDefault(0)
    }

    // libdu sub_d9ca0 (D32): CAMERA_METHODS bits set for methods that are native (hooked)
    private fun checkCameraHook(): Int {
        var mask = 0
        for ((i, pair) in CAMERA_METHODS.withIndex()) {
            runCatching {
                val cls = Class.forName(pair.first)
                if (cls.declaredMethods.any { it.name == pair.second && Modifier.isNative(it.modifiers) }) {
                    mask = mask or (1 shl i)
                }
            }
        }
        return mask
    }

    // libdu sub_d862c (bzt): getDeviceId / getImei / getMeid / getSubscriberId turned native (hooked), one digit each
    private fun checkTelephonyHook(): String = runCatching {
        val methods = Class.forName("android.telephony.TelephonyManager").declaredMethods
        val d0 = if (methods.any { it.name == "getDeviceId" && Modifier.isNative(it.modifiers) }) 1 else 0
        val d1 = if (methods.any { it.name == "getImei" && Modifier.isNative(it.modifiers) }) 1 else 0
        val d2 = if (methods.any { it.name == "getMeid" && Modifier.isNative(it.modifiers) }) 1 else 0
        val d3 = if (methods.any { it.name == "getSubscriberId" && Modifier.isNative(it.modifiers) }) 1 else 0
        "%d%d%d%d".format(d0, d1, d2, d3)
    }.getOrDefault("0000")

    // the file's first line, trimmed; null when empty or unreadable (generic)
    private fun readFirstLine(path: String): String? =
        runCatching { File(path).bufferedReader().use { it.readLine() }?.trim()?.takeIf { it.isNotEmpty() } }.getOrNull()

    // android.os.SystemProperties.get (libdu reads properties inline, no single sub)
    @SuppressLint("PrivateApi")
    private fun prop(key: String, def: String): String = runCatching {
        Class.forName("android.os.SystemProperties").getMethod("get", String::class.java, String::class.java)
            .invoke(null, key, def) as String
    }.getOrDefault(def)
}

// The libdu transforms.
internal object DuCodec {

    private val KEY = "xp7j@&!v5]2k#+3z{n9\$q^r%[8f1*d4e:c>0l?m/6)yb-=w}".toByteArray()

    // Request/response stream cipher: repeating XOR with key-table entry 16.
    fun xor(data: ByteArray): ByteArray = ByteArray(data.size) { (data[it].toInt() xor KEY[it % KEY.size].toInt()).toByte() }

    // libdu sub_df720: middle char first (odd length), then pairs s[n-1-i], s[m-1-i].
    fun shuffle(s: String): String {
        val n = s.length
        val m = n / 2
        val sb = StringBuilder(n)
        if (n % 2 == 1) sb.append(s[m])
        for (i in 0 until m) sb.append(s[n - 1 - i]).append(s[m - 1 - i])
        return sb.toString()
    }

    // Field value obfuscation: every char + 1, then shuffle.
    fun enc(s: String): String = shuffle(s.map { it + 1 }.joinToString(""))

    // libdu sub_f043c with p = 0: drops one char (index n-1-p%10 when n > 9, else the last one).
    fun dropChar(s: String): String = if (s.length <= 1) s else s.substring(0, s.length - 1)

    // Companion of dropChar, stored under "s" + key: MD5(str(sum of chars + p%100/10))[:7]; "CFCD208" for 1-char input.
    fun checksum(s: String): String = if (s.length <= 1) "CFCD208" else md5Upper(s.sumOf { it.code }.toString()).take(7)

    // P1J/AYk: SHA1(android_id) upper, sliced [1:7]:[13:19]:[7:13].
    fun fakeMac(sha1Upper: String): String =
        "${sha1Upper.substring(1, 7)}:${sha1Upper.substring(13, 19)}:${sha1Upper.substring(7, 13)}"

    fun md5Upper(s: String): String = hashHexUpper("MD5", s)

    fun hashHexUpper(alg: String, s: String): String =
        MessageDigest.getInstance(alg).digest(s.toByteArray()).joinToString("") { "%02X".format(it) }
}
