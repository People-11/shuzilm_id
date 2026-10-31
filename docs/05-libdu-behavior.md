# 5. libdu.so 的行为

本章只陈述我们**在客户端观察到的事实**，推断会单独标注。文中括号里的 `E12`、`A3` 等编号是 [`claims.tsv`](data/claims.tsv) 中的核对项，可以用 `verify.py` 对样本重新检查；逐字段的完整数据也可以从样本当场生成，见 [第 4 章](04-tools.md)。

- [5.1 结构与通信](#51-结构与通信)
- [5.2 字段编码](#52-字段编码)
- [5.3 本地持久化](#53-本地持久化)
- [5.4 注册上报 mdna](#54-注册上报-mdna)
- [5.5 环境检测](#55-环境检测)
- [5.6 后续上报：设备信息全量采集](#56-后续上报设备信息全量采集)
- [5.7 跨应用 ID 与其他 SDK 的 ID](#57-跨应用-id-与其他-sdk-的-id)
- [5.8 事件接口](#58-事件接口)
- [5.9 服务器对采集的调度](#59-服务器对采集的调度)
- [5.10 没有覆盖到的部分](#510-没有覆盖到的部分)

## 5.1 结构与通信

### 调用入口

宿主 App 通过 Java 类 `cn.shuzilm.core.DUHelper` 调用 SDK。libdu 在 `JNI_OnLoad` 中用 `RegisterNatives` 注册以下 native 方法（偏移来自 harness `NATIVES=1`）：

| 方法 | 偏移 | 说明 |
|---|---|---|
| `query(Context, String config, String custom, int, long, long, int[])` | `0x13a280` | 主入口：采集、上报、返回设备 ID（`DU...`） |
| `run` | `0x13a250` | |
| `onEvent` / `onIEvent` | `0x13a440` / `0x13a46c` | 分发操作 2 / 3 |
| `dGZvcmRQ(Context, String, String)` | `0x13cf80` | 操作 7，第一个字符串按 JSON 解析 |
| `onSensorChanged(SensorEvent)` | | 传感器事件，见 [5.8](#58-事件接口) |
| `onSSChanged(SignalStrength)` | | 蜂窝信号强度事件 |
| `aXZlZWNl(Context, Intent)` | | 广播 Intent（蓝牙发现），名字是 base64 的 `iveece` |
| `oxlbmV0d(Context, Object, int)`、`ttERIJNQ`、`nYfbIIFp`、`zZVTFJRA`、`c6M2YmYQ`、`c6M3YmYQ`、`ntERIJNQ` | | 其他操作，大多没有逐一分析 |

所有操作最终都进入同一个分发函数 `sub_136838`。

酷安传入的配置（`config`）是：

```json
{"apiKey":"<COOLAPK_APIKEY>","pkglist":"1","operation":"1","cdlmt":"1","l_o":"1"}
```

### 上报格式

1. 各个“构造函数”把采集到的值放进一个 JSONObject（例如首次上报由 `sub_68f9c` 构造），字段键名是三个字符的无意义串（`foO`、`6yY`、`LAh`……），值按 [5.2](#52-字段编码) 编码。
2. JSON 文本经 zlib `compress()` 压缩，再与一个 48 字节的固定密钥做循环 XOR（密钥 `xp7j@&!v5]2k#+3z{n9$q^r%[8f1*d4e:c>0l?m/6)yb-=w}`，是 libdu 内置密钥表的第 16 项）。
3. 通过 HTTPS POST 发出。先尝试 Java 的 `HttpURLConnection`，失败时退回 libdu 自带的 native socket 实现（`sub_3de98`）。传输方式、是否走了回退、耗时等会记进 pref `mtr`，并在下一次上报时作为 `kWV` 发出。
4. 回包同样是循环 XOR 过的 JSON（不压缩）。

mdna 的 URL：

```
https://auni.telecome.cn/a/mdna/report?v=8.7&t=m
    &p=MD5_UPPER("<包名>.37be8a1ee106979a")
    &r=<随机 UUID，无连字符>&n=0&l=2
    &h=0                                  （已有 ID 后为 MD5_UPPER(<ID> + ".889e0b01")）
```

域名是 `telecome.cn`，不是 `telecom.cn`。同一个 libdu 的字符串里还有 `cbsipv4.checktrustworthiness.com`（在 `sub_13a4b8` 中，和 `net_err` 一起出现，用途没有分析）。DuClient 另外把 `global-auni.checktrustworthiness.com` 作为同协议的备用地址，这个域名不在本版本 libdu 的解密字符串里。

成功后，同一次 `query` 中还会继续发出其他类型的上报（[5.6](#56-后续上报设备信息全量采集)）：

| 路径 | 构造函数 | 字段数 | 内容 |
|---|---|---|---|
| `/a/mdna/report?v=8.7&t=m` | `sub_68f9c` | 80+ | 注册，每次 `query` 都发，见 [5.4](#54-注册上报-mdna) |
| `/a/d2api/report?v=8.7&t=a&e=2` | `sub_7f3f4` 等 | ~249 | 设备信息全量 |
| `/a/dcc2/request?v=2.0&c=1&e=1` | | 58 | mdna 字段的子集 + 少量新字段 |
| `/a/audd/valid?v=1.0&t=uid1` | | 47 | 同上 |
| `/a/daa/report?v=1.1&c=1&e=1` | | ~259 | 应用信息 + 与 d2api 相同的全量设备信息 |
| `/a/dai/report?v=2.2&c=1&e=1` | | 45 | 没有单独分析 |

### 回包

mdna 回包中被读取的键（`sub_116f58`、`sub_f2964`）：

| 键 | 去向 |
|---|---|
| `err` | 0 表示成功 |
| `n_a` | 设备 ID（`DU` 开头），写入 pref `n_a` 和外部缓存文件 `e2308fa0`，并作为 `query` 的返回值 |
| `aid` | pref `aid` + 外部缓存文件 `e2dfcfaa` |
| `nctl` | pref `nctl` |
| `cdd`、`ocdd` | pref `cdd`、`sid` |
| `o_a` | pref `o_a`；在后续上报的回包中还会被写到共享存储，见 [5.7](#57-跨应用-id-与其他-sdk-的-id) |
| `dlab` | `<pkg>_dna` 的 `device_label`，AES 加密，下一次上报时解密成 `2mV` |
| `denv`、`isem`、`itime`、`oaid`、`i1`…`i9` | 各自写入 prefs |

## 5.2 字段编码

libdu 的 put 辅助函数 `sub_f07fc` 按“模式”对值编码。编码带一个参数 P，**取自本次上报的时间字段 `2cO`**：

- `2cO` 是 `clock_gettime(CLOCK_REALTIME)` 按 `"%ld.%ld"` 格式化（`sub_c6df0`），纳秒部分不补零；取不到时退回 `gettimeofday`；
- P = `2cO` 最后 3 个字符去掉 `.` 后 `atoi`（`sub_14acbc`，存入 `data_161704`）。每次 `query` 开始时重置（`sub_14b874`），所以同一次查询的所有上报、所有字段共用同一个 P；
- 在真机上，纳秒的末三位基本是随机的，所以每次上报的编码参数都不同。
- 纳秒短于 3 位时，末三位会包含 `.` 和秒的个位：例如 `….7` 取 `4.7` → P = 47，`….1`（秒末位 0）→ P = 1。harness `NSEC` 实测与此一致。

| 模式 | 做法 | 可逆性 |
|---|---|---|
| raw | 原样 | — |
| 2 / 3 | 每个字符在可打印 ASCII（0x20–0x7e）内循环右移 K = `P % 100 % 57 + 1` 位，然后按 `(P / 100) % 4` 选四种重排之一：① 奇数长度先放中间字符，再依次放 `s[n-1-i]`、`s[m-1-i]`（`sub_df720`）；② 依次放 `s[n-1-i]`、`s[i]`，中间字符最后；③ 从末尾起隔一个取一个，再从倒数第二个起隔一个取一个；④ 先取偶数位，再取奇数位 | 完全可逆。P 就写在同一份报文的 `2cO` 里，见 `tools/python/duenc.py` |
| 10 | 去掉第 `n-1-P%10` 个字符（长度 ≤ 9 时去掉最后一个）后按模式 2 编码；另外在 `"s"+键名` 下放校验值 `MD5_UPPER(str(全部字符码位之和 + P%100/10))[:7]` | 完全可逆：校验值能确定被去掉的那个字符 |
| 1、7 | 少数字段使用（`hH1` 蓝牙地址、`9P6` 邻居表），没有逐一核实 | 未核实 |

unidbg 的时钟只有毫秒精度，harness 里 `2cO` 末三位默认是 `000`（P = 0）；用 `NS3` 变量可以强制末三位来验证上面的规则。

以 harness 中的模拟设备为例（P = 0，可以用 `extract_payloads.py` 自己取出来）：

| 字段 | 上报值 | 还原后 |
|---|---|---|
| `foO` + `sfOo` | `4ege81284bfbcc8` + `3BF55BB` | ANDROID_ID `7be317f3baa70ddb`（16 个候选字符中只有一个能匹配校验值） |
| `iYB.Zne` | `f^65;3e054f3g/;2g/g9d742;/c33:d22!;-;51790fgg7\` | `[fe80::1c2b:3cff:fe4d:5e6f/64, 192.168.1.23/24]` |
| `iYB.txo` | `b1mox` | `wlan0` |
| `yzW` | `-msqfnlbdyjfm/dn/pfd` | `com.example.clicker,`（已启用的无障碍服务） |
| `UOv` | `151893:83714141:68/2` | `1793367274.500029800`（开机时间） |
| `BAj` / `DVp` | `616/36/6636/3` / `722//23/:92` | `255.255.255.0` / `192.168.1.1`（子网掩码 / 网关） |

也就是说，所谓“编码”只是字符层面的混淆。去掉传输层的 TLS 和固定密钥 XOR 之后，服务器拿到的就是原始值。只有少数字段在客户端做了真正不可逆的处理（MD5 或只上报检测结果）。

## 5.3 本地持久化

| 位置 | 格式 | 内容 |
|---|---|---|
| `<pkg>_prefs`（SharedPreferences） | 键 = `MD5_UPPER(名字)`；值 = `base64(MD5_UPPER(v) + v)`，或者原样 | 设备 ID（`n_a`）、`aid`、`o_a`、首个 ANDROID_ID（`ndcd`）、`boot_uuid`、启动次数 `boot_times`、首次安装时间 `fut` / 更新时间 `lut`、上次传输统计 `mtr`、各类上报的上次时间（`mdrt`、`uddrt`、`aart`、`acc.dat`、`aio.dat` 等）、服务器下发的调度参数、信号强度 `ss2`、各类传感器读数 `ss3-<type>` 等 |
| `<pkg>_dna`（SharedPreferences） | 明文 | `device_label`（服务器下发，AES 加密）、`ioaid`、`device_id`、`i1`…`i9` |
| `<外部缓存目录>/e2308fa0` | `base64(MD5+v)`，≤128 字节 | 设备 ID |
| `<外部缓存目录>/e2dfcfaa`、`eae6ff4a` | 同上 | `aid`、`nctl` |
| `/sdcard/.o_a`、`/sdcard/Android/Data/System/local/o_a` | `base64(MD5+v)` | 跨应用 ID，见 [5.7](#57-跨应用-id-与其他-sdk-的-id) |
| `/sdcard/Android/ZHVzY2Lk`（base64 的 `duscid`） | | 服务器下发的 `nsci` / `sci` |

**识别“重装后恢复数据”**：SDK 第一次运行时（pref `boot_times` 不存在）会记下 `fut` = 当前安装的 `firstInstallTime`。以后每次上报都会比较这两个值；如果 prefs 还在、`fut` 却和当前安装时间对不上，说明这些 prefs 是从备份或换机工具恢复到了一个新安装里。这时上报 `3k9 = 1`，并把之前保存的设备 ID 作为 `8N4` 一并发出（`sub_140768`、`sub_13d5a4`）。

## 5.4 注册上报 mdna

由 `sub_68f9c(env, ctx, 1)` 构造（一个 762 个状态的平坦化状态机，可以用 `deflat.py sample/libdu.so 68f9c 7a22c x21 auto` 还原），每次 `query` 都会发送。下表是它的主要字段。

“DuClient”一列打 ✓ 的，是 DuClient 实际发送的最小字段集。没有这些字段，服务器不返回 ID。其余字段在 DuClient 中以注释形式保留了实现。

DuClient 发送和注释中列出的键全部属于 mdna，没有后续上报的字段（D1–D19）。

### 身份标识

| 键 | 值 | 如何获得 | 编码 | DuClient |
|---|---|---|---|---|
| `foO` / `sfOo` | ANDROID_ID | `Settings.Secure.ANDROID_ID`（`sub_4bf54`） | 10（可还原） | ✓ |
| `P1J` / `AYk` | 由 ANDROID_ID 派生的“MAC” | `SHA1_UPPER(ANDROID_ID)` 取 `[1:7]:[13:19]:[7:13]`；有了服务器下发的 `o_a` 后，`P1J` 改为 `o_a` | raw | ✓ |
| `6yY` | Widevine 设备唯一 ID | `MediaDrm(edef8ba9-…).getPropertyByteArray("deviceUniqueId")`，hex（`sub_b6e04`） | raw | ✓ |
| `ubF` | 上一次拿到的设备 ID | pref `n_a` / `n_b` / `n_c` / `n_d` 中第一个存在的 | raw | ✓ |
| `dLH` | 每次安装生成的随机 UUID | pref `boot_uuid`，SDK 首次运行时生成（`sub_133048`） | 2 | ✓ |
| `mIS` | 内核本次开机的 boot_id | `/proc/sys/kernel/random/boot_id`（`sub_c6580`） | 2 | |
| `K5f` | 本次上报的 ID | `MD5_UPPER(上报时间串 + pid + rand() + tid)`（`sub_6716c`） | raw | |

### SDK 与协议

| 键 | 值 | DuClient |
|---|---|---|
| `75c` | 宿主的 apiKey | ✓ |
| `DUv` | 宿主包名 | ✓ |
| `3mS` | SDK 版本 `v9.0.1` | ✓ |
| `AAA` / `BBB` | `v1.0` / `v1.0` | ✓ |
| `UOv` | 开机时刻：`CLOCK_REALTIME - CLOCK_BOOTTIME`，`"%ld.%ld"`（`sub_c70f8`），模式 2 | ✓ |
| `2cO` | 本次上报时间：`clock_gettime(CLOCK_REALTIME)` 的 `"%ld.%ld"`，纳秒不补零（`sub_c6df0`）。末三位同时决定本次上报全部字段的编码参数 P，见 [5.2](#52-字段编码) | ✓ |
| `ne8` | libdu.so 自身的 MD5（`sub_ea898`；推断：用来检测 SDK 是否被替换） | |
| `msg` | 宿主传入的自定义 JSON（酷安传 `{"custom":""}`） | |
| `GVp` | 渠道（`DefaultChannel`） | |
| `fxb` | `100000 + 本地小时 × 20 + rand() % 10 ± 1`（`sub_6869c`） | |
| `B3k` | 构造这个 payload 花了多少毫秒 | |
| `Db2` / `cHo` | 常量 2 / 0 | |

### 设备与系统

| 键 | 值 | 如何获得 | DuClient |
|---|---|---|---|
| `R37` / `R3d` | 厂商 / 型号 | `Build.MANUFACTURER` / `Build.MODEL` | ✓ |
| `R41` / `SAN` | 系统版本 / API 级别 | `Build.VERSION.RELEASE` / `SDK_INT` | ✓ |
| `R53` | `ro.debuggable` | 系统属性 | |
| `R63` | `init.svc.adbd`（adbd 是否在运行） | 系统属性 | |
| `Ra` / `R5a` | SIM 状态 / 运营商代码 | `gsm.sim.state` / `gsm.operator.numeric` | |
| `R1e` | `net.hostname` | 系统属性，模式 2 | |
| `S6e` | SELinux 是否 enforcing | `/sys/fs/selinux/enforce` | |
| `fPV` | 国家,语言 | `Locale.getDefault()` | |
| `h6Z` | 宿主 App 的显示名称 | `getApplicationLabel` | |
| `EV2` / `Zrs` / `h8h` | 宿主版本名 / 版本号 / longVersionCode | `PackageInfo` | |
| `Qg1` / `LMi` | 宿主首次安装时间 / 最后更新时间 | `PackageInfo` | |
| `G8U.MYA` | `MemTotal,MemFree`（kB） | `/proc/meminfo` 前 5 行（`sub_b19b4`） | |
| `G8U.H4S` | `/data` 总容量,可用容量（GiB） | `statfs` | |

### 文件系统与硬件指纹

这些字段单独看都不是“ID”，但组合起来几乎每台设备都不同，其中不少（inode、分区参数、硬件序列号、系统库摘要）在刷机或恢复出厂之前一直不变。

| 键 | 值 | 如何获得 | 编码 |
|---|---|---|---|
| `ibF` | 根分区 fsid + 块数 + inode 数 | `statfs("/")`，`"%x%x-%ld-%ld"`（`sub_c003c`） | 2 |
| `52J` | 10 个路径的 inode:dev | `lstat` `/sdcard`、`/system/lib`、`/system/lib64`、`/system/bin`、`/sys/block`、`/vendor/lib`、`/dev/null`、`/dev/block`、`/storage/emulated/0`、`/system/vendor`（`sub_cb304`） | 2 |
| `aFw`、`Bos`、`IAI`、`IJK`、`QNw`、`ura` | 目录的访问/修改时间（纳秒精度） | `stat` `/data/system`、`/sdcard/Android/data/.nomedia`、`DCIM`、`/storage/emulated/0`、`/sdcard/Android/data/com.google.android.gms`、`/storage/self/primary` | 2 |
| `KyU` | 宿主 `shared_prefs` 目录的访问时间 | `stat`（`sub_bf0ec`） | 2 |
| `p1m` | eMMC 序列号 | `/sys/block/mmcblk0/device/serial` | 2 |
| `dJs` | eMMC CID | `/sys/block/mmcblk0/device/cid` 前 32 字节 | 2 |
| `GZY` | SoC 序列号 | `/sys/devices/soc0/serial_number` | 2 |
| `w91` | `/system/fonts` 文件名列表的 MD5 | `readdir`（`sub_bba60`） | raw |
| `gEd` | `libreference-ril.so` 或 `libc.so`（32 位）的 MD5 | 读文件（`sub_bc530`） | raw |
| `5Tv` | `/system/lib64/libcutils.so` 的 MD5 | 读文件（`sub_bc404`） | 2 |
| `zvW` | Canvas 指纹 | 在一张 64×64 的内置 PNG 上画径向渐变和一串混合了中、阿、日文的文字，对像素取 MD5（`sub_c8934`） | 2 |
| `YWu` | **hosts 文件内容** | `/system/etc/hosts`，每行 `ip+host;`，最多 511 字符（`sub_d82f4`） | raw |

`YWu` 值得单独说一句：用 hosts 文件屏蔽广告或跟踪域名的用户，这份屏蔽列表的开头会原样上报。

### 网络

| 键 | 值 | 如何获得 | 编码 |
|---|---|---|---|
| `iYB` | 当前网络：接口名 `txo`、全部 IP 地址 `Zne`、DNS 服务器 `MCN`、HTTP 代理主机 `9X9` / 端口 `dki`、传输类型位图 `AWo`、传输类型名 `mch`、上下行带宽 `8tS` / `Hsz` | `ConnectivityManager` + `LinkProperties` + `NetworkCapabilities`（`sub_b3fe0`） | 2（代理主机 raw） |
| `7S2` | **所有**网络的接口名、IP、DNS | `getAllNetworks()`（`sub_b3b6c`） | 2 |
| `wSK` | Wi-Fi 的 DHCP 地址 | `WifiManager.getDhcpInfo()`（`sub_b275c`） | raw |
| `zpA` / `ozK` | 网络类型 / 子类型名 | `getActiveNetworkInfo()` | raw |
| `J7w` | 移动数据是否打开 | `isDataEnabled` / `getMobileDataEnabled`（`sub_b6220`） | raw |

### 硬件与电话标识

| 键 | 值 | 如何获得 | 编码 |
|---|---|---|---|
| `41j` / `nyx` / `M96` | wlan0 / wlan1 / p2p0 的 MAC | `/sys/class/net/*/address`，否则 `ip link`；`11:22:33:44:55:66`、`02:00:00:00:00:00` 等占位值不算数（`sub_4adb4`、`sub_c2198`、`sub_c21b8`） | 10 |
| `fM0` | 推算出的**出厂 MAC** | Android 9+ 上 wlan0 给的是随机 MAC 时，用 wlan1 / p2p0 的地址（驱动通常由出厂 MAC 派生）反推出厂地址（`sub_4afb4`，Kotlin 移植与原函数在 3000 组随机输入上结果一致） | 10 |
| `p92` / `3J5` | IMEI / DeviceId | `getDeviceId()` 或 `getImei()`，需要 `READ_PHONE_STATE`（`sub_a535c` / `sub_a5544`）；宿主可以通过 `DUHelper.mMeic` 关闭 | 10 |
| `LkB` | 数据网络类型 | `getDataNetworkType()` | raw |
| `JPd` / `bf7` / `4VP` | SIM 运营商 / 注册网络运营商 / SIM 状态 | `TelephonyManager` | raw |
| `IOe` / `q6I` | 系统设置里的 OAID / 华为 `pps_oaid` | `Settings.Secure/Global` | 3 |
| `fV5`、`JCE`、`CVi`……共 21 个 | 各厂商广告 ID：`asaid suaid mzaid nbaid gaid hwaid hrid laid voaid opaid sanl xmid onepid mtid zteid fmid ssuid pzid cpid ebkd exoid`；另有 `za7` = 获取时间 | 由 SDK 的 Java 层写进 `<pkg>_prefs`，native 读取（`sub_51d44`） | 3 |
| 14 个模拟器属性 | `bst.machine_id`、`nemud.player_uuid`、`ro.microvirt.hmac`、`persist.nox.device_id`、`vmprop.androidid`…… | 系统属性（`sub_7dbec`），存在时才上报 | 2 |

### 来自 SDK 历史状态的字段

这些字段不会出现在一台设备的第一次上报里，只在 SDK 之前的运行留下了状态后才出现。我们在 harness 中伪造成功回包、连续查询两次确认了这一点：

| 键 | 值 |
|---|---|
| `dGh` | 第一次上报时的 ANDROID_ID（pref `ndcd`）。之后即使 ANDROID_ID 被改掉（例如用改机工具），服务器仍能看到最初的值 |
| `kWV` | 上一次上报的 `K5f`、传输方式、是否回退、回退耗时、总耗时 |
| `wHp` / `nAt` | 服务器下发的 `aid` / `nctl` |
| `w5v` | 宿主是否出现在 `getPackagesHoldingPermissions(INTERNET)` 的结果里，以及安装时间是否一致：0 一致，1 不一致，2 列表不可用（`sub_aa7b0`）。推断：用来检测宿主是否运行在多开或虚拟环境里 |
| `2mV` | 服务器下发的设备标签：`<pkg>_dna device_label` 用 `MD5_UPPER("<pkg>.54bc01a66a")[:16]` 做 AES/ECB 解密 |
| `v1X` | 跨应用 ID `/sdcard/.o_a`，见 [5.7](#57-跨应用-id-与其他-sdk-的-id) |
| `3k9` / `8N4` | prefs 被恢复到了新安装里 / 之前保存的设备 ID，见 [5.3](#53-本地持久化) |
| `My2` | 宿主配置的 partnerCode（酷安没有传） |

## 5.5 环境检测

检测项由 `sub_61074` 一组函数完成（zc7 在 d2api 中）。下表每一行都在 harness 中实测过：先在干净环境里跑一次，再分别伪造对应的应用、文件或 Hook 跑一次，比较字段值（核对项见最后一列）。

- “干净”和“检出”两列都是**原值**。标为 mode 2 的字段会按本次上报的 P 编码（[5.2](#52-字段编码)），所以线上看到的值随 P 变化。例如干净设备的 LAh，P = 0 时线上是 `11111111`，P = 281 时是 `IIIIIIII`。
- “是否安装”统一用 `PackageManager.getApplicationIcon(包名)` 判断：不抛 `NameNotFoundException` 就算已安装。
- 带 `?` 的结论，是模拟环境没有触发、只做了静态核对的部分。

| 键 | 编码 | 检测什么 | 怎么检测 | 干净 | 检出 | 核对项 |
|---|---|---|---|---|---|---|
| `tth` | 原样 | Root 管理器 | 逐个查询 14 个包名：SuperSU、Superuser、KingRoot、Magisk Alpha、KernelSU、Fox's Magisk Module Manager……（`sub_cd8ac`） | 0 | 1 | E1–E3 |
| `QgA` | 原样 | su 程序 | `stat` 约 40 个路径（`/system/bin/su`、`/system/xbin/su`、`/sbin/su`、`/apex/com.android.art/bin/su`、`/data/local/su`、SuperSU 守护进程文件等），最后执行 `which su`（`sub_c36e8`） | 0 | 1 | E4、E5 |
| `90P` | mode 2 | Magisk / Xposed 系框架 | 第 1 位：`access` 28 个特征文件（`/sbin/.magisk`、`/data/adb/magisk`、`/data/adb/lspd`、riru / EdXposed / 太极 / 梦境模块目录、`XposedBridge.jar`、`libxposed_art.so` 等，`sub_cfdc8`），或者 `/proc/mounts` 中出现 `magisk`（`sub_cd1ac`）；第 2 位的含义没有确定 | `00` | `10` | E6–E11 |
| `LAh` | mode 2 | 8 类 Hook / 虚拟化 / 改机 / 隐藏工具，每类一位 | 查询 18 个包名。按位依次是：① Magisk（含 Delta）② Xposed Installer ③ EdXposed、VirtualXposed ④ LSPosed / LSPatch ⑤ Substrate ⑥ 改机工具 `com.soft.apk008v`、Shizuku ⑦ `com.yztc.studio.plugin` ⑧ `com.uwish.app`、HideMyApplist、HideMyRoot、太极、Dreamland（`sub_cec90`） | `00000000` | 对应位为 1 | E12–E21 |
| `zc7` | 原样 | 进程内的注入框架（d2api） | 第 1 位：`/proc/self/maps` 中出现 xposed / lspd / riru / xhook 等特征；第 2 位：maps 中出现 frida；第 3 位：LSPosed / EdXposed 文件存在；第 4 位：干净环境下也是 1，含义没有确定。此外还遍历 `/proc/self/fd` 和 `/proc/self/task`，查找 frida 线程名（`sub_d1910` → `sub_cb96c`） | `0001` | 如 frida → `0101` | E29–E33 |
| `Xl9` | 原样 | 虚拟摄像头（进程内） | 第 1、2 位：`/proc/self/maps` 中出现 `sandyz` / `virtualcam`；第 3、4 位：某个应用的 `Android/data/<包名>/cache/` 下有 `stream.txt` / `virtual.mp4`（`sub_d9980`） | `0000` | 对应位为 1 | E22–E26 |
| `Chh` | 原样 | 虚拟摄像头（相册目录） | `DCIM/Camera1/` 下的 `virtual.mp4`、`disable.jpg`、`no-silent.jpg`、`no_toast.jpg`、`private_dir.jpg`、`force_show.jpg`、`1000.bmp`，或者 `Android/data/<包名>/files/Camera1/virtual.mp4`（`sub_d96ec`） | 0 | 1 | E27、E28 |
| `D32` | 原样 | 相机方法被 Hook（虚拟摄像头） | `Camera.setPreviewCallback`、`setPreviewCallbackWithBuffer`、`startPreview`、`CameraDeviceImpl.createCaptureSession`、`ImageReader.newInstance` 是否被改成 native，每个一位（`sub_d9ca0`） | 0 | 如 `startPreview` → 4 | E36 |
| `bzt` | 原样 | 电话标识方法被 Hook（改机） | `TelephonyManager.getDeviceId / getImei / getMeid / getSubscriberId` 是否被改成 native，每个一位（`sub_d862c`） | `0000` | 如 `getImei` → `0100` | E35 |
| `5mZ` | 原样 | TLS 校验方法被 Hook（抓包绕过） | 11 个证书校验相关方法（`TrustManagerImpl.checkServerTrusted`、`SSLContext.init`、`CertPinManager.isChainValid` 等）是否被改成 native，每个一位（`sub_d8e1c`） | 0 | 如 `SSLContext.init` → 16 | E37 |
| `0KQ` | 原样 | TLS 校验被全局关闭 | 默认 TrustManager 是否接受**空证书链**（`sub_d90e4`） | 0 | 1 ? | E38 |
| `iZS` | 原样 | 调试器 | `/proc/self/status` 中 `TracerPid` 的原值（`sub_c82e0`） | 0 | 调试器的 pid | E34 |
| `ZZA` | 原样 | VPN | `access` `/sys/class/net/tun0`、`ppp0`、`tap0`（`sub_bc708`） | 0 | 1 | E39 |
| `nur` | 原样 | 自动点击 / 脚本工具 | 逐个查询 31 个包名：按键精灵、触动精灵、Auto.js、各种自动点击器……（`sub_cd32c`） | 0 | 1 | E40 |
| `qH9` | 原样 | 沙箱是否完整 | 宿主数据目录的上级目录（`%s/..`）能否 `opendir`（`sub_972a0`） | `0` | `1` ? | E44 |
| `c2O` / `PV8` | 原样 | 开发者选项 | `Settings.Global` 中 `adb_enabled` / `stay_on_while_plugged_in` 的原值 | `0` | 设置值 | E43 |
| `wlM` | 原样 | USB 连接与 ADB | 粘性广播 `USB_STATE`（`sub_cec88`），模拟环境没有触发 | 0 | ? | — |
| `QVn` | 原样 | 权限 | 宿主是否获得粗略定位、精确定位、附近 Wi-Fi、电话等权限，每项一位（`sub_9200c`） | 视宿主而定 | | E45 |
| `yzW` | mode 2 | 已启用的无障碍服务 | 每个服务的**包名**，逗号分隔（`sub_976a0`） | 不上报 | 包名列表 | E41 |
| `Q23` | 原样 | 用户安装的 CA 证书 | `AndroidCAStore` 中 `user:` 开头的别名加签发者，最多 1023 字符（`sub_d7dd4`） | 不上报 | 证书列表 ? | E42 |
| `S6e`、`R53`、`R63` | 原样 | SELinux / 可调试 / adbd | 见 5.4 | 1 / 0 / stopped | | |

注意 `yzW` 和 `Q23` 上报的不是“有 / 没有”，而是具体内容：开了哪些无障碍服务（读屏软件、自动化工具、密码管理器……），装了哪些自签证书（抓包工具、企业代理……）。

虚拟摄像头一共查了三处：`D32` 查相机方法有没有被 Hook，`Xl9` 查进程和应用目录，`Chh` 查相册目录。这类工具常被用来在人脸核验时“播放”预先录好的视频。

## 5.6 后续上报：设备信息全量采集

mdna 成功后，同一次 `query` 里会继续发送 d2api、dcc2、audd、daa 等上报（[5.1](#51-结构与通信)）。其中 d2api 和 daa 各有约 250 个字段，在 mdna 的基础上增加了下面这些内容。

除特别说明外，需要权限的项只在宿主已获得该权限时采集。

| 类别 | 键 | 内容 | 如何获得 |
|---|---|---|---|
| **其他 SDK 的设备 ID** | `tbA` / `tLE` | 百度设备 ID | `Settings.System` `com.baidu.deviceid` / `bd_setting_i` |
| | `ZCk` | 数美设备 ID | `Settings.System` `com.shumei.deviceid` |
| | `e4U` / `F9K` | 阿里 UTDID | `Settings.System` `mqBRboGZkQPcAkyk` / `dxCRMxhQkdGePGnp` |
| | （`I68` 附近） | 字节跳动 AppLog / 穿山甲 的设备 ID | 宿主 SharedPreferences `embed_applog_stats` 的 `device_id`、`ttopenadsdk` 的 `did` |
| | `OWY` | 某 SDK 的 SQLite 库 | 打开并查询 `databases/zx.db`（`sub_ee314`） |
| | `go9` / `fEs` / `pcJ` | 小米健康 ID / OPPO 安全 UUID / 设备序列号 | `Settings.Global` `mi_health_id` / `op_security_uuid` / `device_serial` |
| | `v5q` | 另一 SDK 写在共享存储上的 ID | `/sdcard/..ccvid`、`/sdcard/Android/Data/System/local/.ccvid` |
| **其他 App** | `mbU` | 微信、支付宝、QQ 的首次安装时间 | `getPackageInfo`，`"%ld,%ld,%ld"`（`sub_ac650`） |
| | `ZQM` | 微信 APK 的路径（判断是否分身） | `ApplicationInfo.sourceDir`（`sub_ac768`） |
| | `T2t` | 宿主是从哪个应用商店安装的 | `getInstallerPackageName`（`sub_acd98`） |
| | `6PH` | 当前有网络连接的 App | 解析 `/proc/net/tcp`、`tcp6`、`udp`、`udp6`，按 uid 对应到包名（`sub_92540`） |
| | `OW2` | 进程列表 | 执行 `ps \| grep u0_a<uid>`（`sub_d9e00`） |
| | `psg` | 是否正在录屏 / 投屏 | appops `DetectActiveMediaProjection` 等（`sub_940f8`） |
| | `5Nc` / `zUN` | 默认桌面 / 默认输入法 | `ACTION_MAIN + CATEGORY_HOME` / `default_input_method` |
| | `z4m` | 已启用的无障碍服务（与厂商白名单比较） | `enabled_accessibility_services` |
| | `pT4` / `SAu` / `Cl5` | 宿主签名摘要 / 签名证书主体 / 宿主 APK 路径 | `PackageManager`、`CertificateFactory` |
| **周边网络与设备** | `9P6` | **局域网邻居表**：路由器和同网段其他设备的 IP 与 MAC | 执行 `ip neigh` + netlink 邻居查询（`sub_c2740`） |
| | `Dg1` | **周围的 Wi-Fi 扫描结果** | `WifiManager.getScanResults()`，需要粗略定位权限（`sub_b4754`） |
| | `IPz` / `jK5` | 当前 Wi-Fi 的 SSID / BSSID（路由器 MAC） | `WifiInfo`（`jK5` 模式 10） |
| | `Ufi` | **已配对的蓝牙设备** | `BluetoothAdapter.getBondedDevices()`，需要 `BLUETOOTH_CONNECT`（`sub_ba150`） |
| | `hH1` / `iXj` | 本机蓝牙地址 / 蓝牙名称 | `Settings.Secure` `bluetooth_address` / `bluetooth_name` |
| | `BAj` / `DVp` | 子网掩码 / 网关 | `DhcpInfo` |
| | `02P`、`59p`、`uG4`、`JIi`、`z4e`、`JYD` | Wi-Fi 链路速率、Wi-Fi 7 MLO 链路、Wi-Fi 状态与标准 | `WifiInfo` |
| | `9N2` / `Bn2` | 移动数据流量 / 总流量（收、发字节数） | `TrafficStats` |
| | `43c` / `CzO` | 系统 HTTP 代理 | `http.proxyHost` / `http.proxyPort` |
| | `1yT` | 是否开启了 MAC 随机化 | `wifi_connected_mac_randomization_enabled` |
| | `EmH` / `g5k` / `ISX` | eth0 / eth1 / eth2 的 MAC | `/sys/class/net/ethN/address`（模式 10） |
| | `kZJ` | 设备管理员可读的 Wi-Fi MAC | `DevicePolicyManager.getWifiMacAddress` |
| | `LFE` | 蓝牙地址文件路径 | `ro.bt.bdaddr_path` |
| **电话** | `dj3` | ICCID（SIM 卡序列号） | `getSimSerialNumber` / 订阅信息（`sub_a6438`） |
| | `Yko` | IMSI | `getSubscriberId`（模式 10） |
| | `XFU` / `lPc` / `Uae` / `sJN` | 活动订阅、各卡槽信息、卡数 | `SubscriptionManager`、`phone2` / `phone_msim` |
| | `LDA` | 基带软件版本 | `getDeviceSoftwareVersion` |
| | `hdw` / `NoH` | VoLTE、锁屏是否设置密码、漫游 | `Settings`、`KeyguardManager` |
| | `n1R` | 连接的 USB 设备 | `UsbManager.getDeviceList()` |
| **硬件与系统** | `vB2` 内约 70 个 `R*` 键 | 构建信息全量：指纹、bootloader、基带、radio、时区…… | 系统属性 |
| | `oJI` | 传感器列表 | `getSensorList(TYPE_ALL)` |
| | `Fi3` / `TwQ` | 显示器列表 / 显示参数 | `DisplayManager`、`DisplayMetrics` |
| | `uCM` | 电池状态 | `ACTION_BATTERY_CHANGED` |
| | `8ET` | GNSS 芯片型号 | `getGnssHardwareModelName` |
| | `IHa` | WebView UA | `WebSettings.getDefaultUserAgent` |
| | `kYm` | 内核版本 | `/proc/sys/kernel/osrelease`、`/proc/version`、`uname -a` |
| | `cgU` / `eHZ` / `Aop` / `IPV` | 温度 / CPU 最大、当前频率 / CPU 核心 | `/sys/class/thermal/...`、`/sys/devices/system/cpu/...` |
| | `XH7` / `vv1` / `NAB` / `sCc` | 音量 / 铃声模式 / 屏幕是否亮着 / 是否在交互 | `AudioManager`、`PowerManager` |
| | `7Gf` / `anY` | 无障碍是否开启 / 设备管理员是否激活 | |
| | `Hg6` / `Pxm` / `qdK` / `WSZ` | 开机时间 / `date` 命令输出 / elapsedRealtimeNanos / uptime | `/proc/uptime` 等 |
| | `ED2` | 随机 UUID | `/proc/sys/kernel/random/uuid` |
| | `9lc` / `JEw` / `IJs` | 进程 cgroup / uid、gid / 数据目录 | `/proc/self/cgroup` 等 |
| | `fej` | 硬件密钥库探测 | 在 AndroidKeyStore 中生成一个 EC 密钥 `du_tkai_<时间>_<n>_<pid>`（字符串表里有 `setAttestationChallenge`），然后删除 |
| | `eBI` | 时区数据库版本 | `/data/misc/zoneinfo/current/tzdata`、`/system/usr/share/zoneinfo/tzdata` |
| | `7Hz` | `/data/local/tmp` 的访问/修改时间（推断：用来判断是否用 adb 推送过文件） | `stat` |
| | `XmW` / `Ell` | SDK 自己记录的 MAC 历史 / 另一个状态文件 | `/89ca503b`、`/ee02ad45` |

这张表是按类别挑出的代表字段，没有列全。全部约 250 个字段及其来源函数、解出的字符串，可以用 `keys_sources.py` 生成。

## 5.7 跨应用 ID 与其他 SDK 的 ID

### 共享存储上的跨应用 ID

在一类后续上报（内部类型 6，由 `sub_7f3f4` 构造，回包由 `sub_11f7f0` 处理，很可能就是 d2api）的回包里，如果带有至少 11 个字符的 `o_a`，并且宿主没有关闭这项功能（`data_163418 != 0x2718`），libdu 会通过 shell 执行：

```sh
mkdir /sdcard/Android/Data/System/local/
echo <base64(MD5(o_a) + o_a)> > /sdcard/Android/Data/System/local/o_a
echo <base64(MD5(o_a) + o_a)> > /sdcard/.o_a
```

（实际路径写成 `/sdcard/../../../../../../sdcard/...`，`sub_ef53c`，命令由 `sub_ee084` 以 `popen` 执行，核对项 X8–X10。）

之后**任何集成了这个 SDK 的 App**，在 mdna 中都会读取这个文件，作为 `v1X` 上报（`sub_ef3f8`）。同一个回包处理函数还会把 `nsci` 写进 `/sdcard/Android/ZHVzY2Lk`（base64 的 `duscid`），后续上报中的 `Kvk` 就是这个文件的 MD5（文件不存在时取一个新随机 UUID 的 MD5）。

这意味着：

- 这个 ID 放在共享存储上，**卸载 App 不会删除它**，清除 App 数据也不会；
- 同一台设备上的不同 App（不同开发者、不同签名）通过这个文件拿到同一个值，**Android 8 起 ANDROID_ID 按签名隔离，本来是为了防止这种跨应用关联，这个文件让这层保护失效**；
- 文件在共享存储上，任何有存储权限的 App 都能读，不只是集成了数盟 SDK 的 App。

由于 unidbg 不支持 exec，这段 shell 写入在 harness 里没有真正执行，以上内容来自静态分析（写入函数解出的命令字符串）。读取一侧在 harness 里能看到：mdna 会打开 `/sdcard/.o_a` 等文件（核对项 X7）。作用域存储（Android 11+）下宿主还能否写入 `/sdcard` 根目录，取决于宿主的存储权限，我们没有在真机上验证。

### 写进系统设置的跨应用 ID

共享存储之外还有第二条通道：**Settings.System**。这是系统级的设置表，所有应用都能读取。

- 回包处理函数 `sub_11f7f0` 会把服务器下发的 `nsci` / `sci` 以 `ZHVzY2Lk` 和 `duscid` 两个键名写进 Settings.System（经 `sub_b1274` → `sub_b114c`，`Settings.System.putString`；核对项 X11–X14）；
- `sub_b10b4` 还会写一个名为 `dxCRMxhQDPkdGePG` 的键。这个名字与阿里 UTDID 使用的 `dxCRMxhQkdGePGnp` 几乎一样（核对项 X15）；
- 两处写入都先检查宿主有没有 `WRITE_SETTINGS`。这是一项需要用户在系统设置里单独授予的特殊权限，大多数应用没有；
- 读取一侧不需要任何权限：mdna 会从 Settings.System 读取 `duscid` 和 `ZHVzY2Lk`（核对项 X16）。也就是说，只要有一个获得了 `WRITE_SETTINGS` 的应用写入过，同一台设备上其他所有接入 SDK 的应用都能读到。

### 读取其他 SDK 的 ID

见 [5.6](#56-后续上报设备信息全量采集) 的第一组：百度、数美、阿里 UTDID、字节跳动 AppLog、穿山甲的设备 ID，以及其他 SDK 写在共享存储（`..ccvid`）和数据库（`zx.db`）里的标识，都会被读取并上报。其中，百度、数美、UTDID 是从 Settings.System 读的，字节跳动和穿山甲的 ID 读自宿主的 `embed_applog_stats` / `ttopenadsdk` SharedPreferences（核对项 X1–X7）。另外 mdna 本身还读取 21 个厂商广告 ID（[5.4](#54-注册上报-mdna)）。

## 5.8 事件接口

除了 `query` 这种一次性的采集，libdu 还导出了几个接收**持续事件**的 native 方法：

| 方法 | 输入 | 处理 |
|---|---|---|
| `onSensorChanged(SensorEvent)` | 传感器事件 | 按传感器类型保存读数到 pref `ss3-<type>`，供后续上报使用 |
| `onSSChanged(SignalStrength)` | 蜂窝信号强度 | dBm、LTE RSRP / RSRQ / RSSNR 存入 pref `ss2` |
| `aXZlZWNl(Context, Intent)` | 广播 | 处理蓝牙发现的 `ACTION_FOUND`：附近设备的地址、名称、信号强度、设备类别，按 `"%s,%s,%d,%d;"` 累积 |

也就是说，只要宿主（或 SDK 的 Java 层）注册了相应的监听，SDK 就能拿到持续的传感器数据、信号强度，以及**附近蓝牙设备的扫描结果**。daa 上报中的 `ciD` / `awt` / `kaU` 三个全局 JSON 对象由这些路径填充（具体哪个对象对应哪类事件没有核实）。

SDK 的 Java 部分没有分析（[3.2](03-sample.md#32-sdk-的-java-部分)），所以“谁在什么时候注册这些监听”我们不知道。我们确认的只是：native 层具备完整的处理逻辑。

## 5.9 服务器对采集的调度

d2api 回包由 `sub_11b8d8` 处理。它读取一批混淆过的键，写入对应的 prefs：

| 回包键 | pref | 含义（推断） |
|---|---|---|
| `Pbs` | `down_t` | 各类后续上报的下次执行时间 / 间隔 |
| `yns` | `udd_t` | 同上 |
| `T9s` | `dai_t` | 同上 |
| `SBW` / `a59` / `fLS` / `PWh` / `0bm` / `f1V` | `ld_t` / `cfg_t` / `ncht` / `ptsk` / `downs` / `clso` | 同上，以及配置 |
| `itime` / `EC3` | `imdrt` / `parr2` | 模式 3 存储 |
| `NXF`、`ueJ`、`Qz9`、`VP8`、`LCS`、`C1G`、`jUl`、`TQa`、`nnt`、`2sW{VrJ,Vt9,cYD}`、`6mi`、`C49`、`6Up`、`OKF`、`CdN` | — | 与 `"0"` / `"1"` / `"2"` 比较的开关 |

推断：以 `_t` 结尾的 pref 是各类后续上报上一次的执行时间。哪些上报要做、多久做一次，由服务器通过回包下发的开关和间隔决定。换句话说，客户端实际采集什么，可以由服务器远程调整，而不是固定在 SDK 版本里。

## 5.10 没有覆盖到的部分

- **需要权限、真机或服务器配合才会出现的字段**：`02P 0q1 0wL 1yT 3pD 59p 6PH 9P6 Blv Bsy Dg1 EIx Ell EmH Hg6 IPz ISX JcY Lcq Nue OEu OW2 Pxm QvM SAu Slq Sxg T5u TV5 TpT` 等，在 harness 中没有实际运行到。它们的来源只能从静态字符串判断（`keys_sources.py` 的输出）。
- **静态无法确定键名的 put 点**：`keys_sources.py` 输出中键为 `?` 的行没有逐一确认。
- **只做了静态核对的字段**：表中标 `?` 的项，以及 5.6 中需要权限的大部分字段（核对项 A6–A20 只检查了“由哪个函数采集、该函数用到哪些字符串”）。
- **d2api 回包中各个开关的具体含义**：只确认了它们写到哪个 pref、和什么值比较。
- **其他 native 操作**：`sub_136838` 分发的 `ttERIJNQ`、`nYfbIIFp`、`zZVTFJRA` 等。
- **SDK 的 Java 层**：完全没有分析。
- **服务端**：服务器如何使用这些数据、如何计算风险、ID 和数据保存多久，我们看不到。第 6 章的相关内容都是推断。
