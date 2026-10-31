# 3. 样本说明

## 3.1 libdu.so

| 项目 | 值 |
|---|---|
| 来源 | 酷安官方客户端 16.6.4（versionCode 2609291），arm64-v8a 版本 APK 内的 `lib/arm64-v8a/libdu.so` |
| 所属 | 北京数字联盟网络科技有限公司「可信 ID SDK」的 native 部分（Java 类 `cn.shuzilm.core.DUHelper` / `Main` / `AIClient`） |
| SDK 版本串 | `v9.0.1`（payload 字段 `3mS`），上报协议 `v=8.7` |
| 大小 | 1,417,064 字节 |
| SHA-256 | `9e08c9323dd1ba439c6232658fee0a9e29283800a1d61bd429747f5bae997d0d` |
| MD5 | `97313e29420c51d0d8cc6e3a3586889a`（libdu 自己也会算这个值并上报为 `ne8`） |
| 来源 APK SHA-256 | `9a2be68a5dbb500f40fdd5e183ef36388dec676caaaa23a5a872429ddbba9eff`（`CoolApk-16.6.4-2609291-coolapk-arm64-sign.apk`，APK 本身不随仓库分发） |

校验：

```sh
cd sample
sha256sum -c SHA256SUMS     # libdu.so 和 DuClient.kt
md5sum -c MD5SUMS
```

保护措施（分析时遇到的，见 [5.1](05-libdu-behavior.md#51-结构与通信)）：

- 绝大部分函数做了 OLLVM 风格的控制流平坦化，分发器里还有基于全局变量的不透明谓词；
- 字符串全部加密，运行时由 `sub_1143bc` 解密（`out[k] = (b[2k+1] - 1) ^ k`），少数敏感字符串（例如 `/sbin/.magisk`、frida 特征）在栈上逐字节 XOR 拼出；
- JNI 方法通过 `RegisterNatives` 动态注册，所有操作经过一个总分发函数 `sub_136838`。

本文中所有 `sub_xxxxx` 都是这个文件里的函数偏移（文件偏移 = 虚拟地址）。换了版本的 libdu.so 偏移都会变，但字段键名（`foO`、`6yY`……）在不同宿主 App 之间应当一致，因为服务器按这些键解析。

## 3.2 SDK 的 Java 部分

宿主 App 里的数盟 Java 代码经过加壳/混淆，本项目**没有**对它做分析。所以凡是 Java 层负责的行为，本文只能从 native 一侧推断，例如：

- 21 个厂商广告 ID（OAID 类，见 [5.4](05-libdu-behavior.md#54-注册上报-mdna)）由 Java 层写入 `<pkg>_prefs`，native 只读取；
- 传感器、信号强度、蓝牙扫描这些事件由谁、在什么时候注册监听，native 里只能看到处理函数。

## 3.3 DuClient.kt

`sample/DuClient.kt` 是我们为第三方客户端用纯 Kotlin 重写的 `DUHelper.query`：不加载 libdu.so，只构造并发送一次 mdna 注册上报，拿回服务器下发的 `DU...` 设备 ID。

- **它是什么**：一份“可运行的注释”。文件里列出了 libdu mdna 注册上报的每一个字段、每个字段在 libdu 里由哪个函数采集、怎么编码，以及每项环境检测的“安全值”。其中**真正发送的只有十几个字段**（身份、SDK 版本、机型、系统版本），其余全部以注释形式保留，作为对 libdu 行为的逐字段说明。注释里列出的也都是 mdna 字段（核对项 D1–D19）。
- **它不是什么**：不是 libdu 的反编译代码，也不是完整的协议实现。它不实现后续的 d2api / dcc2 / audd / daa 上报，不实现回包中的调度逻辑，也不读取其他 SDK 的 ID。
- **在本仓库中的改动**：Coolapk 在 SDK 初始化时传入的 `apiKey`（数盟分配给酷安的客户密钥）已替换为 `<COOLAPK_APIKEY>`；去掉了对原工程设置类的依赖（机型直接取 `Build`，宿主版本号改为占位常量），包名改为 `shuzilm.sample`。采集与编码逻辑未改动。
- **依赖**：只依赖 Android SDK 和 `org.json`，可以放进任意 Android 工程编译；宿主版本号常量需要自己填写。

### 当前局限

1. 只覆盖 Coolapk 16.6.4 所带的 libdu v9.0.1；SDK 升级后字段、加密常量和偏移都可能变化。
2. 只发送最小字段集。服务器对这种“信息很少”的设备会给出什么样的风险评价，我们无法从客户端看到。
3. 服务器的判定逻辑完全是黑盒。本文对服务端的一切描述都是根据客户端行为和数盟公开资料做的推断，会明确标注。
4. 部分字段只在特定权限、特定系统版本或特定服务器回包下才会出现，模拟环境里跑不到，见 [5.10](05-libdu-behavior.md#510-没有覆盖到的部分)。

## 3.4 关于样本的脱敏

- 不分发 APK，不分发酷安自身的任何代码。
- 酷安的 `apiKey` 已在 `DuClient.kt`、harness 默认配置和所有示例 payload 中替换为 `<COOLAPK_APIKEY>`。
- 文档中引用的上报示例值全部来自模拟环境：一台虚构的 Pixel 7（Android 14），ANDROID_ID、Widevine ID 等由种子生成，IP、MAC、包名均为占位值，**不对应任何真实设备或真实用户**。
- 分析早期（2026-10-16），为了确认服务器是否会给模拟环境发 ID、以及 ID 如何随设备种子变化，我们曾把模拟环境生成的上报原样转发到数盟服务器，两个种子共约 10 次请求。此后这条路径一直关闭，本仓库发布的 harness 也已删除这段转发代码：网络层只记录请求，回包全部由本地环境变量构造（见 [4.4](04-tools.md#44-harness)）。
