# 4. 工具与环境搭建

我们的分析分两条线：

- **静态分析**：Python 脚本，基于 capstone（反汇编）和 unicorn（单函数模拟执行）。负责解字符串、把字段键名定位到采集函数、还原被平坦化的状态机。
- **动态分析**：基于 [unidbg](https://github.com/zhkl0228/unidbg) 的 Java harness。它在 PC 上模拟出一台假的 Android 设备，加载 libdu.so，调用真实的 `DUHelper.query`，记录 libdu 发起的每一次 JNI 调用、属性读取、文件访问，以及最终构造的上报明文。

逆向过程中还用到了 jadx（看宿主 App 怎么调用 SDK）和 Binary Ninja（交叉核对个别函数）。这两个是通用的大型工具，不随仓库分发，也不是复现本文结论的必需品。

## 4.1 目录

```
tools/
  python/          静态分析脚本（全部只读输入文件，不联网）
  data/            由 libdu.so 派生的中间数据，脚本的默认输入
    relocs.txt       readelf -rW 的输出（GOT / 重定位，解字符串要用）
    funcs.txt        函数起始地址（来自 .eh_frame_hdr）
    strings.txt      全部加密字符串的引用点
    funcstr_all.txt  每个函数解出的字符串（funcstr.py 的输出）
    keysites.txt     每个字段键名的加载点及所在函数（keysites.py 的输出）
    sm_68f9c.txt     mdna 构造函数 sub_68f9c 的状态机（deflat.py 的输出，762 个状态）
    flow_68f9c.txt   sub_68f9c 中每个 put 的键与值来源（flow.py 的输出）
    leafstr_out.txt  栈上 XOR 字符串采集函数的 libc 调用记录（leafstr.py 的输出）
  harness/         unidbg harness（Maven 工程）
docs/data/
  keys_catalog.tsv 每个上报类型的全部字段、出现在哪些上报里、示例值和解码值
  keys_sources.tsv 每个字段的构造函数、put 位置、编码模式、值来源函数及其字符串
  payload_*.json   harness 中捕获的五类上报明文（模拟设备，apiKey 已脱敏）
```

## 4.2 Python 环境

测试环境：Python 3.12、capstone 5.0.9、unicorn 2.1.4，Windows 11（Linux / macOS 也可以，脚本里没有平台相关代码）。

```sh
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install capstone==5.0.9 unicorn==2.1.4
```

建议始终用 `python -I` 运行（隔离模式，不从当前目录导入模块）。另外不要把自己的脚本命名为 `dis.py`：它会遮蔽标准库的 `dis`，导致 unicorn 导入失败。

如果要自己重新生成 `relocs.txt`：

```sh
llvm-readelf -rW sample/libdu.so > tools/data/relocs.txt     # 或 aarch64-linux-gnu-readelf
```

### 常用脚本

以下命令都在仓库根目录执行，`S=sample/libdu.so`，`D=tools/data`。

| 脚本 | 用途 | 示例 |
|---|---|---|
| `d.py` | 按主方案解密指定地址的字符串（`out[k] = (b[2k+1]-1) ^ k`） | `python -I tools/python/d.py $S 0x146b5` |
| `decstr.py` / `funcidx.py` | 扫描全部字符串解密调用点 / 按函数归类 | 见文件头注释 |
| `funcstr.py` | 每个函数解出的全部字符串 | `python -I tools/python/funcstr.py $S $D/relocs.txt $D/funcs.txt > funcstr_all.txt` |
| `keysites.py` | 每个字段键名在哪里被加载、属于哪个函数、紧接着调用了哪个 put | `python -I tools/python/keysites.py $S $D/relocs.txt $D/funcs.txt` |
| `flow.py` | 对平坦化后的构造函数做栈槽数据流分析：每个 put 的键和值分别来自哪里 | `python -I tools/python/flow.py $S $D/relocs.txt 68f9c 7a22c` |
| `deflat.py` | 还原 OLLVM 状态机：状态 → 处理块里的调用 → 后继状态及条件 | `python -I tools/python/deflat.py $S $D/relocs.txt 68f9c 7a22c x21 auto > sm.txt` |
| `smprint.py` / `smwin.py` / `smpath.py` | 以可读形式浏览状态机 / 某状态附近 / 从入口到某指令的最短路径及条件 | `python -I tools/python/smpath.py sm.txt 0x6d310` |
| `memref.py` | 哪些代码读写了某个全局地址 | `python -I tools/python/memref.py $S 0x161700` |
| `disasm.py` | 线性反汇编一段地址 | `python -I tools/python/disasm.py $S 4afb4 4b200` |
| `ucall.py` | 在 unicorn 里单独调用一个 libdu 函数，libc 和指定的内部函数用 Python 桩替代 | 见下 |
| `leafstr.py` | 用 ucall 跑“叶子”采集函数并记录它的 libc 调用，读出栈上 XOR 拼出的路径和命令 | `python -I tools/python/leafstr.py 0xbc708` |
| `test_fm0.py` | 把 `sub_4afb4`（fM0）和 DuClient 中的 Kotlin 移植放在 3000 组随机 MAC 上对比 | `python -I tools/python/test_fm0.py` → `cases 3000 mismatches 0` |
| `unenc.py` | 解码 P = 0 时的 mode 2/3 字段值（编码见 [5.2](05-libdu-behavior.md#52-字段编码)） | `python -I tools/python/unenc.py b1mox` → `wlan0` |
| `duenc.py` | 按任意 `2cO` 编码 / 解码 mode 2/3/10 字段（含自检断言） | `python -I tools/python/duenc.py 1791105420.764024281 dec bb_p` → `WIFI` |
| `catalog.py` | 由 payload 生成字段目录（`keys_catalog.tsv`） | `python -I tools/python/catalog.py docs/data/payload_*.json` |
| `apkcert.py` | 从 APK 签名块（v2/v3）提取签名证书，harness 需要 | `python -I tools/python/apkcert.py app.apk tools/harness/coolapk_cert.der` |

`ucall.py` 默认读取 `sample/libdu.so` 和 `tools/data/relocs.txt`，可以用环境变量 `LIBDU`、`RELOCS` 覆盖：

```python
import ucall
u = ucall.U()
u.stub(0x4adb4, lambda u: u.cstr_new("02:11:22:33:44:55"))   # 用固定值替代 wlan0 MAC 读取
print(hex(u.call(0x4afb4, 1, 2)))
```

处理 harness 日志的脚本：`decode_payload.py`（取出 mdna 明文并解码字段）、`payloads.py` / `pdiff.py`（多次查询的字段差异）、`prefs.py`（运行结束时 SDK 的 SharedPreferences，键名还原、值解码）、`fm2.py` / `fieldmap.py`（某个字段写入前发生了哪些读取，也就是值从哪来）、`fnflow.py` / `span.py`（FNTRACE 的函数调用序列）。

## 4.3 unidbg harness

### 依赖

- JDK 17 或更新版本（我们用 OpenJDK 25 测试过）
- Maven 3.9.x
- 依赖都从 Maven Central 获取：`com.github.zhkl0228:unidbg-android:0.9.9`、`org.json:json`、`slf4j-simple`
- 酷安 APK 的签名证书 `coolapk_cert.der`。libdu 会读取宿主签名并上报其摘要，harness 需要用真实证书伪装成宿主。证书属于公开信息，但仓库不分发，请自行从 APK 中提取：

```sh
python -I tools/python/apkcert.py CoolApk-16.6.4-2609291-coolapk-arm64-sign.apk tools/harness/coolapk_cert.der
```

### 构建与运行

```sh
cd tools/harness
mvn -q compile dependency:build-classpath -Dmdep.outputFile=cp.txt

# 运行（Windows 的 classpath 分隔符是 ;，Linux / macOS 是 :）
PATCH_KEYCHECK=1 RICH=1 A7=60000 java -cp "target/classes;$(cat cp.txt)" du.Harness      # 默认加载 ../../sample/libdu.so
```

运行后会在当前目录生成：

- `trace.log`：每一次 JNI 调用（类、方法、参数、返回值）、系统属性读取（`PROP`）、`openat` 等系统调用、网络请求（`NET URL` / `NET BODY` / `NET SEND`），以及压缩前的上报明文（`COMPRESS@...`）；
- `unidbg.log`：unidbg 自身的日志。

接着可以：

```sh
python -I ../python/decode_payload.py trace.log     # mdna 明文，mode 2/3 字段自动解码
python -I ../python/prefs.py trace.log              # SDK 留下的 prefs
```

每次运行默认清空 `target/rootfs`，相当于全新安装。设置 `KEEPFS=1` 可以保留上次运行写下的“sdcard”和私有目录。

### 网络

harness **不联网**。libdu 的 HTTP 请求走 Java 的 `HttpURLConnection`，在 JNI 层被截获：请求只写进日志，回包由环境变量构造：

- 不设置 `RESP_JSON` / `RESP_RAW_HEX` 时，返回 HTTP 599，libdu 走失败分支；
- `RESP_JSON='{...}'` 会用 libdu 的 XOR 密钥加密这段 JSON 后作为回包返回，libdu 随后走成功分支，并继续发送后续上报。

### 环境变量

| 变量 | 作用 |
|---|---|
| `APIKEY` | 传给 SDK 的 apiKey。默认是占位符，需要配合 `PATCH_KEYCHECK=1` 使用 |
| `PATCH_KEYCHECK=1` | 把 apiKey 格式校验函数（`0x147214`）补丁成永远通过 |
| `RICH=1` | 打开一组更丰富的假数据（文件、Java 调用、网络能力等），让依赖这些数据的可选字段出现在 payload 里 |
| `QUERIES=n` | 在同一个进程里调用 `query` n 次。后面的调用能看到前面留下的 prefs 和文件（模拟同一安装的第 2、3 次启动） |
| `RESP_JSON` / `RESP_RAW_HEX` | 伪造服务器回包（JSON 会被 XOR 加密；HEX 是原始字节） |
| `A7` | `query` 的超时参数（毫秒），建议 60000 |
| `DEVICE_SEED` / `SEED_AID` / `SEED_WV` / `ANDROID_ID` | 假设备的种子：Widevine ID 和 ANDROID_ID 由种子派生，也可以直接指定 ANDROID_ID |
| `TRANSPORT` | `NetworkCapabilities.hasTransport` 返回 true 的传输类型（默认 1 = Wi-Fi） |
| `LUT_SEQ=v1,v2,...` | `lastUpdateTime` 逐次读取返回的值（用来区分 `getPackageInfo` 与已安装列表两条读取路径） |
| `PREFS_SET=name=value,...` | 预先写入 `<pkg>_prefs`（键做 MD5 哈希，值原样存放，与 Java 层写入方式相同） |
| `CALLS='sig\|arg\|i:1#sig\|...'` | 查询结束后再调用其他 `DUHelper` native 方法；参数中 `i:` 前缀表示整数，其余按字符串处理 |
| `NATIVES=1` | 打印 `JNI_OnLoad` 注册的全部 native 方法及偏移 |
| `FNTRACE=1` | 记录进入每个已知函数（`../data/funcs.txt`）时的 x0–x2 和返回地址，日志会很大 |
| `CODEDUMP=off1,off2` | 执行到这些偏移时打印全部寄存器，以及寄存器指向的字符串 |
| `WATCH=addr` | 记录对某个绝对地址的写入 |
| `FUNCTEST=0xoff:input,...` | 直接调用 `fn(char* buf, len)` 形式的函数并打印结果 |
| `KEYTABLE=1` | 打印 libdu 内置的密钥表 |
| `KEEPFS=1` | 不清空模拟文件系统 |
| `NS3=281` | 把传给 `sub_14b500` 的 `2cO` 末三位改成指定值（unidbg 时钟只有毫秒精度，末三位总是 000），用来观察字段编码参数 P 的影响 |
| `NSEC=42` | 把 `2cO` 的整个纳秒部分换成指定值（libdu 不补零，短于 3 位时末三位会带上 `.` 和秒的末位） |
| `IDLE` / `MAXRUN` | 看门狗：日志停止增长 IDLE 秒（默认 30），或总运行时间超过 MAXRUN 秒（默认 600）就退出 |

### 复现“首次上报 + 后续上报”

```sh
PATCH_KEYCHECK=1 RICH=1 A7=60000 QUERIES=2 \
RESP_JSON='{"err":"0","n_a":"DU0000000000000000000000000000000000000000000000000000TEST","aid":"AID_TEST","o_a":"OA22222222222","cdd":"CDD_TEST","nctl":"1"}' \
java -cp "target/classes;$(cat cp.txt)" du.Harness

grep -a -o "NET SEND Conn(https://[^/]*/a/[a-z0-9]*/[a-z]*" trace.log | sort | uniq -c
python -I ../python/pdiff.py trace.log        # 第二次 mdna 与第一次相比多了哪些字段
python -I ../python/prefs.py trace.log
```

我们最后一次运行（2026-10-31）的结果：两次 `mdna/report`，之后依次是 `d2api/report`（2 次）、`dcc2/request`、`audd/valid`、`daa/report`、`dai/report`；第二次 mdna 带上了 `dGh`、`kWV`、`nAt`、`ubF`、`w5v`、`wHp`，`P1J` 换成了回包里的 `o_a`。

### 模拟设备的局限

- 假设备是一台虚构的 Pixel 7（Android 14）。系统属性见 `Props.java`，Java 层的返回值见 `AndroidFakes.java` 和 `RichFakes.java`。没有伪造的 JNI 调用会记录为 `MISSES`，返回 null 或 0。
- unidbg 不支持 fork / exec，所以通过 shell 执行的命令（`ip neigh`、`ps`、`echo ... > /sdcard/.o_a` 等）在 harness 里不会真正执行。这些命令的内容是从静态分析和 `leafstr.py` 里读出来的。
- 需要危险权限的采集（电话、定位、蓝牙、Wi-Fi 扫描）大多被假数据挡在了权限检查处，相关字段只能靠静态分析，见 [5.10](05-libdu-behavior.md#510-没有覆盖到的部分)。
