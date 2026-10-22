# 安全盾 SafeShield

一个 macOS 原生安全防护应用的学习实践案例，完整保留了从需求调研到可运行程序的文档链与代码。适合想学习「一个桌面应用如何从零设计、开发、打包」的人参考。

## 它是什么

安全盾面向 macOS 个人用户与轻量终端，提供两种工作模式：

- **体检模式**：对系统配置、隐私权限、启动项、文件、网络、账户六类维度做一次性快照检测，按规则权重打分并给出修复引导。
- **守护模式**：建立基线后做运行时差分监控（进程、端口、外连、启动项、受控目录、账户的新增/篡改变化），产生分级告警。
- **处置框架**：对告警项提供隔离、终止、封禁等动作，全部经过策略门控与二次确认，只读姿态不执行任何处置，处置可审计、可回滚。

技术栈：Swift + SwiftUI（AppKit/CryptoKit），无 Xcode 工程依赖，用 `swiftc` 直接编译后手工组装 `.app` bundle。所有数据仅存本机，不读取、不上传文件内容与口令。

## 目录结构

```
├── 00-安全盾SafeShield-整合版总方案.md   # 立项：问题、目标、总体架构、路线图
├── 01-安全体检应用方案.md               # 早期体检子方案
├── 02-安全盾SafeShield-PRD.md           # 产品需求：功能条目 + 优先级 + 验收标准
├── 03-安全盾SafeShield-开发设计.md       # 开发设计：模块、接口、数据结构、实现偏差实录
├── 安全盾SafeShield-界面Demo.html        # 界面交互原型（单文件，mock 数据）
├── app/                                 # 完整原生应用源码
│   ├── Sources/                         # Swift 源码（Core 引擎 / App 界面 / Guardian 守护 / Response 处置 / Store 存储）
│   ├── Resources/                       # 规则库 rules.default.json、图标
│   ├── build.sh                         # 命令行构建脚本
│   └── build/SafeShield.app/            # 已编译的应用成品
├── mvp/SafeShieldMVP.swift              # 早期单文件 MVP（最小可运行验证）
└── dist/                                # 安装说明与校验和
```

## 怎么读这套案例

按软件工程的推进顺序看，能清楚看到一个想法如何逐步落地：

1. **先读 `00` 总方案**：要解决什么问题、为什么这样做、边界在哪、分几个阶段做。
2. **再读 `02` PRD**：功能被拆成带优先级（P0/P1/P2）的需求条目，每条都有「给定—当—那么」的可测验收标准。
3. **接着读 `03` 开发设计**：模块划分、数据结构、规则引擎评分口径，以及 §17「实现偏差与工程实录」——记录了落地时遇到的真实坑（如管道死锁、宏插件缺失、路径判定修正），这部分对学习者最有价值。
4. **打开 `安全盾SafeShield-界面Demo.html`**：浏览器直接打开即可交互，先理解界面信息架构，再对照 `app/Sources/` 看 SwiftUI 怎么实现。
5. **读源码**：`Core/` 是检测与评分引擎，`Guardian/` 是基线差分，`Response/` 是处置门控，`App/` 是界面，`Store/` 是本地存储。

## 如何编译运行

需要 macOS 与 Command Line Tools（含 `swiftc`）。

```bash
cd app
./build.sh                 # 编译生成 build/SafeShield.app
open build/SafeShield.app
```

应用未做 Apple 签名与公证，首次打开如被 Gatekeeper 拦截，可在访达中右键应用选择「打开」。

自动化验证参数（仅供测试/演示）：

```bash
build/SafeShield.app/Contents/MacOS/SafeShield --selftest    # 处置链路合规自检
build/SafeShield.app/Contents/MacOS/SafeShield --headless    # 无界面跑一次体检并打印评分
```

如需生成 `.dmg` 安装包，可在本机执行：

```bash
hdiutil create -volname "SafeShield" -srcfolder app/build -ov -format UDZO dist/SafeShield-0.9.0.dmg
```

## 关于数据

本案例中的检测逻辑只读取本机系统配置与元数据，所有结果仅存储在本机 `~/Library/Application Support/SafeShield/`，不联网、不上传。文档中出现的评分与检测示例均为通用演示数据。

## 许可

MIT License，见 `LICENSE`。可自由用于学习与二次开发。
