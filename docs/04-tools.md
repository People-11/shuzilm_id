# 4. 工具与验证

你不需要相信我们。本章说明怎样用仓库里的工具，对 `sample/libdu.so` 自己核对第 5 章的结论。

- **只想确认结论成立**：装好环境（4.1）后跑一条命令（4.2）。
- **想亲眼看某一条是怎么来的**：4.3 给出了几类常用命令。
- **想自己继续分析**：4.4 介绍 harness，4.5 是脚本一览。

仓库里**没有**放任何中间数据。字符串表、字段来源表、上报样例都由脚本从 `sample/libdu.so` 当场生成，所以你看到的一定是这份样本本身的内容。

## 4.1 环境

**Python**（必需）。测试过的版本是 Python 3.12、capstone 5.0.9、unicorn 2.1.4；Windows、Linux、macOS 都可以。

```sh
pip install capstone==5.0.9 unicorn==2.1.4
```

所有命令都在仓库根目录用 `python -I` 运行（隔离模式，不从当前目录导入模块）。

**Java harness**（只有运行时核对需要）。要求 JDK 17 或更新版本、Maven 3.9.x，依赖从 Maven Central 获取。还需要酷安 APK 的签名证书：libdu 会读取宿主签名，harness 要用它来伪装宿主。证书是公开信息，但仓库不分发，请自行从 APK 中提取：

```sh
python -I tools/python/apkcert.py CoolApk-16.6.4-2609291-coolapk-arm64-sign.apk tools/harness/coolapk_cert.der
cd tools/harness && mvn -q compile dependency:build-classpath -Dmdep.outputFile=cp.txt && cd ../..
```

## 4.2 一键核对

```sh
python -I tools/python/verify.py --no-harness     # 只做静态核对，不需要 Java
python -I tools/python/verify.py                  # 全部核对（会跑约 40 次 harness，几分钟）
python -I tools/python/verify.py --only E12,E17   # 只查指定的核对项
```

核对项列在 [`docs/data/claims.tsv`](data/claims.tsv)，每行对应文档里的一处结论，第 5 章正文中括号里的 `E12`、`A3` 就是它们的编号。输出逐行给出 `PASS` / `FAIL` 和实际看到的值；只要有一项 FAIL，退出码就是 1。

核对项分以下几种。想核对文档里的其他说法，可以照同样的格式往 `claims.tsv` 里加一行。

| 类型 | 检查什么 | 例子 |
|---|---|---|
| `static` | 键 K 的值来自函数 X，且 X 解出了指定字符串；可以再限定由哪个上报构造函数写入 | A1：`mbU` 来自 `sub_ac650`，它用到 `com.tencent.mm`、`com.eg.android.AlipayGphone`、`com.tencent.mobileqq` |
| `str` / `call` | 函数解出了指定字符串 / 以指定参数调用另一个函数 | X13：`sub_11f7f0` 用 `"ZHVzY2Lk"` 调用写 Settings.System 的函数 |
| `leaf` | 单独运行某个采集函数时，它访问的文件、执行的命令里有指定内容 | E4：`sub_c36e8` 会 `stat('/system/xbin/su')`，并执行 `which su` |
| `run` | 在指定场景下跑一次 harness（伪造已安装的应用、文件或 Hook），键 K 的值等于期望值 | E17：只“安装”LSPosed 时，LAh 解码后是 `00010000` |
| `read` | harness 日志里出现了指定的读取 | X5：从 Settings.System 读取 `com.baidu.deviceid` |
| `report` | 在指定场景下跑一次 harness，某类上报（如 mdna）压缩前的明文里出现了全部指定的键 | D1：DuClient 实际发送的 17 个键都在 mdna 里 |
| `mode` | 把 `2cO` 末三位分别设为 000 和 281 各跑一次，看键 K 的值是否随之变化，以此判断它是编码字段还是原样字段 | E8：90P 是编码字段 |

## 4.3 自己看

**某个字段从哪来**。列出每个 put 点的键、编码模式、值来源函数及该函数用到的字符串：

```sh
python -I tools/python/keys_sources.py sample/libdu.so > keys_sources.tsv
grep -P "^mbU\t" keys_sources.tsv
```

键为 `?` 的行，是静态分析无法确定键名的 put 点（几个键共用同一个 put 调用，或者键名不是常量）。这些要靠下面的运行时归因。

**某个函数里有哪些字符串**：`python -I tools/python/funcstr.py sample/libdu.so`，每行一个函数。

**栈上拼出来的字符串**。有些采集函数的路径和命令是在栈上逐字节 XOR 出来的，静态扫描看不到。可以把函数单独放进模拟器里跑，记录它访问了什么：

```sh
python -I tools/python/leafrun.py c36e8        # su 检测：约 40 个 stat，再执行 which su
python -I tools/python/leafrun.py d9980        # Xl9：maps 里找 sandyz / virtualcam，再查 Android/data/*/cache
```

**真正发出去的上报**。跑一次 harness，取出每类上报压缩前的明文，再做运行时归因：

```sh
cd tools/harness
java -cp "target/classes;$(cat cp.txt)" du.Harness        # 环境变量见下方示例；Linux / macOS 的分隔符用 :
python -I ../python/extract_payloads.py trace.log .       # payload_mdna.json、payload_d2api.json ……
python -I ../python/attribute.py trace.log > keys_runtime.tsv
python -I ../python/prefs.py trace.log                    # SDK 留在 SharedPreferences 里的东西
```

`keys_runtime.tsv` 对每个键给出它的值、按本次上报的 P 解码后的值，以及写入之前发生的读取，例如对哪些包名调用了 `getPackageInfo`、打开了哪些文件。

**解码某个字段**：`python -I tools/python/duenc.py <2cO> dec <值>`，参数 P 取自同一份报文的 `2cO`（见 5.2）。

## 4.4 harness

harness 用 [unidbg](https://github.com/zhkl0228/unidbg) 在 PC 上模拟一台虚构的 Pixel 7（Android 14），加载 libdu.so 并调用真实的 `DUHelper.query`。它**不联网**：HTTP 请求在 JNI 层被截获，只记录不发送，回包由 `RESP_JSON` 构造。

一次包含后续上报的完整运行：

```sh
cd tools/harness
PATCH_KEYCHECK=1 RICH=1 A7=60000 QUERIES=2 \
RESP_JSON='{"err":"0","n_a":"DU0000000000000000000000000000000000000000000000000000TEST","aid":"AID_TEST","o_a":"OA22222222222","cdd":"CDD_TEST","nctl":"1"}' \
java -cp "target/classes;$(cat cp.txt)" du.Harness
```

运行后生成 `trace.log`，记录每一次 JNI 调用、系统属性读取、文件相关的系统调用、网络请求，以及压缩前的上报明文。

常用环境变量：

| 变量 | 作用 |
|---|---|
| `PATCH_KEYCHECK=1` | 跳过 apiKey 格式校验（仓库里的 apiKey 是占位符） |
| `RICH=1` | 打开一组更丰富的假数据，让更多可选字段出现 |
| `RESP_JSON='{...}'` | 伪造服务器回包；没有它时 libdu 走失败分支，不发后续上报 |
| `QUERIES=n` | 同一进程内连续查询 n 次，模拟同一安装的多次启动 |
| `INSTALLED=pkg1,pkg2` | 让这些包看起来已安装 |
| `FAKEFILE='path=内容;…'` | 加入伪造文件（`\n` 表示换行），`open` / `access` / `stat` 都认，例如 su、`/proc/self/maps` 里的 frida |
| `NATIVE='类名#方法名,…'` | 让反射看到这些方法是 native 的，模拟被 Hook |
| `NS3=281` / `NSEC=42` | 改写 `2cO` 的末三位 / 整个纳秒部分，观察字段编码参数 P |
| `ANDROID_ID` / `DEVICE_SEED` | 指定 ANDROID_ID / 用种子派生假设备的各种 ID |
| `FNTRACE=<文件>` | 记录进入每个函数的情况（文件由 `python -I tools/python/elf.py sample/libdu.so funcs` 生成），`attribute.py` 用它列出“采集函数”一栏 |
| `PROPS='键=值,…'` | 覆盖或添加系统属性，例如模拟器特有的 `bst.machine_id` |
| `USERCA='别名=签发者,…'` | 在 `AndroidCAStore` 里加入用户安装的 CA 证书（别名以 `user:` 开头） |
| `PROXY=主机:端口` / `SUBTYPE=LTE` | 当前网络的 HTTP 代理 / 网络子类型名 |
| `KEEPFS=1` | 不清空模拟文件系统（可以先在 `target/rootfs/default/` 下手工放好文件） |

更多调试用的开关（`CODEDUMP`、`WATCH`、`CALLS`、`PREFS_SET` 等）见 `Harness.java` 中的注释。

注意事项：

- 在 Windows 的 Git Bash 里，以 `/` 开头的环境变量值会被自动改写成 Windows 路径，`FAKEFILE='/system/xbin/su=x'` 会因此失效。先执行 `export MSYS2_ENV_CONV_EXCL='*'`（`verify.py` 会自动处理）。
- unidbg 不支持 fork / exec，所以通过 shell 执行的命令（`ip neigh`、`which su`、`echo … > /sdcard/.o_a`）不会真正执行。这些命令的内容来自静态分析和 `leafrun.py`。
- 需要危险权限的采集（电话、定位、蓝牙、Wi-Fi 扫描）大多停在了权限检查处，只能做静态核对，见 [5.10](05-libdu-behavior.md#510-没有覆盖到的部分)。

## 4.5 脚本一览

所有脚本只需要 `sample/libdu.so` 这一个输入，用法写在各文件开头。

| 脚本 | 用途 |
|---|---|
| `verify.py` | 按 `claims.tsv` 逐条核对 |
| `keys_sources.py` | 每个字段的静态来源 |
| `funcstr.py` / `keysites.py` | 每个函数解出的字符串 / 每个键名的加载位置 |
| `flow.py` | 平坦化函数的栈槽数据流：每个调用的参数来自哪里 |
| `deflat.py` | 还原 OLLVM 状态机 |
| `leafrun.py` / `ucall.py` | 在 unicorn 中单独运行 libdu 函数 |
| `duenc.py` | 字段编码 / 解码（含自检断言） |
| `attribute.py` / `extract_payloads.py` / `prefs.py` | 处理 harness 的 `trace.log` |
| `test_fm0.py` | 拿 DuClient 推算出厂 MAC 的 Kotlin 移植，与 libdu 原函数比对 3000 组随机输入 |
| `elf.py` | 读取 libdu.so 的重定位表和函数表（其他脚本都用它） |
| `apkcert.py` | 从 APK 提取签名证书 |
