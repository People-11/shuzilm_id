# shuzilm_id

**数字联盟（shuzilm）可信 ID SDK 设备数据采集分析与有责任的披露**

数字联盟的“可信 ID SDK”被大量国内 App 集成，用来给每台手机发一个“设备唯一 ID”。我们在为第三方客户端重写它的设备注册流程时，逆向了 SDK 的 native 库 `libdu.so`（v9.0.1）。我们发现，它上报的远不止一个设备标识，而是一份完整的设备环境档案。这份档案通过跨应用稳定的 ID，在所有接入了 SDK 的 App 之间共享。

## 主要发现

- **首次注册就发送 80 多个字段**（视设备而定），之后的全量上报每份还有约 250 个字段。真正拿到 ID 只需要其中十几个（[5.4](docs/05-libdu-behavior.md#54-首次注册上报-mdna)）。
- **环境检测**：Root / su / Magisk 挂载、Xposed / LSPosed / Frida、调试器、TLS 证书校验 Hook、系统是否接受空证书链、虚拟摄像头、改机、自动点击工具、SELinux、ADB、VPN……（[5.5](docs/05-libdu-behavior.md#55-环境检测)）
- **上报的是具体内容，不只是检测结果**：hosts 文件内容、用户安装的 CA 证书、已启用的无障碍服务包名、所有网络接口的 IP 与 DNS（[5.4](docs/05-libdu-behavior.md#54-首次注册上报-mdna)）。
- **周边环境**：局域网邻居的 IP 与 MAC、周围 Wi-Fi 扫描结果、已配对蓝牙设备；native 层还有处理附近蓝牙设备扫描、传感器、信号强度事件的接口（[5.6](docs/05-libdu-behavior.md#56-后续上报设备信息全量采集)、[5.8](docs/05-libdu-behavior.md#58-事件接口)）。
- **读取其他公司 SDK 的设备 ID**：百度、数美、阿里 UTDID、字节跳动 AppLog、穿山甲等（[5.7](docs/05-libdu-behavior.md#57-跨应用-id-与其他-sdk-的-id)）。
- **跨应用 ID**：服务器下发的 `o_a` 会通过 shell 写进 `/sdcard/.o_a`。卸载后仍然存在，所有集成了 SDK 的 App 都会读取并上报它（[5.7](docs/05-libdu-behavior.md#57-跨应用-id-与其他-sdk-的-id)）。
- **“编码”可逆**：绝大多数字段只是字符 +1 加重排。ANDROID_ID 可以从上报中完整还原，Widevine 设备 ID 原样上报。这与隐私政策中“本地脱敏”“服务器不收集任何设备原始数据”的说法不符（[5.2](docs/05-libdu-behavior.md#52-字段编码)、[6.2](docs/06-shuzilm.md#62-隐私政策的说法与我们的观察)）。
- **推断**：数盟宣称为设备保存“历史风险标签”。所以接入方拿到你的 ID 就能查到这台设备的环境状况：你在这个 App 里藏得再好，只要在任何一个接入了 SDK 的 App 里没藏住就够了（[6.3](docs/06-shuzilm.md#63-推断一个-id-能告诉别人什么)）。

## 文档

1. [动机](docs/01-motivation.md)
2. [有责任的披露](docs/02-responsible-disclosure.md)：原则、刻意不公开的内容、时间线
3. [样本说明](docs/03-sample.md)：libdu.so 的来源与哈希、DuClient.kt 是什么、局限
4. [工具与环境搭建](docs/04-tools.md)：Python 静态分析脚本、unidbg harness 的构建与使用
5. [libdu.so 的行为](docs/05-libdu-behavior.md)：通信、编码、持久化、逐字段说明
6. [数字联盟：一个设备 ID 背后意味着什么](docs/06-shuzilm.md)：官网自述、隐私政策对照、推断

## 仓库结构

```
sample/       libdu.so 样本、校验值、DuClient.kt（纯 Kotlin 的最小实现，apiKey 已脱敏）
tools/
  python/     静态分析脚本（capstone / unicorn）
  data/       由样本派生的中间数据（重定位、函数表、解密字符串、状态机……）
  harness/    unidbg harness：在 PC 上模拟一台假的 Android 设备运行 libdu.so
docs/         文档
  data/       全部字段的目录与来源表、模拟设备上捕获的五类上报明文
```

## 范围与声明

- 分析对象是酷安 16.6.4 客户端内置的 `libdu.so` v9.0.1（SHA-256 `9e08c932…ae997d0d`）。其他版本可能不同。
- 客户端行为是事实，可以用本仓库的工具复核；关于服务端的内容都是推断，文中会标注。
- 本仓库不包含任何真实用户或真实设备的数据，不提供客户密钥，也不提供向数盟服务器批量提交伪造数据的工具。
- `sample/libdu.so` 的版权属于北京数字联盟网络科技有限公司，仅为验证目的收录。

---

## English summary

This repository documents what the native part (`libdu.so`, v9.0.1) of Shuzilm's (数字联盟) "Trusted ID" device-fingerprinting SDK, embedded in many Chinese Android apps, actually collects. We reverse engineered it while reimplementing its device registration in pure Kotlin for a third-party client.

Beyond a device identifier, every registration report carries a full environment snapshot. This includes root / Magisk / Xposed / Frida / debugger detection, TLS-pinning-bypass checks, and the contents of the hosts file. It also sends user-installed CA certificates, enabled accessibility services, and every interface's IP and DNS addresses. Follow-up reports add LAN neighbours' MACs, Wi-Fi scan results, bonded Bluetooth devices, and other vendors' device IDs (Baidu, Shumei, Alibaba UTDID, ByteDance, Pangle). The SDK also writes a server-issued cross-app ID to shared storage (`/sdcard/.o_a`), which outlives uninstallation and is read by every app that embeds the SDK.

Field "encoding" is a reversible character shift and shuffle. ANDROID_ID can be fully recovered from the report, and the Widevine device ID is sent as-is. That contradicts the vendor's privacy policy, which says data is desensitised on the device.

All client-side claims cite function offsets in the included sample and can be checked with the included tools. Server-side statements are marked as inference. The documentation is in Chinese.
