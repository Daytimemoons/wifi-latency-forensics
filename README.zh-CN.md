# wifi-latency-forensics

**网络会毫无征兆地变成"两秒延迟"，持续几分钟后又自己好了——等你打开网络工具，它又正常了。**

这个工具专门针对这种故障：**在它正在发生的时候**启动，用固定时长把无线链路、驱动事件日志、本机负载和报文路径全部录下来，跑完自动生成关联分析报告，然后自己退出。

```
Run-NetWatch.cmd  →  录制 20 分钟  →  report.md / report.html  →  自动退出
```

不需要安装程序、不需要常驻服务、不上报任何数据、不需要云端账号。Windows 自带 PowerShell 5.1 就够。

> English documentation: **[README.md](README.md)**
> 这个工具诞生的真实案例（已脱敏）：**[docs/case-study-2026-10-18.md](docs/case-study-2026-10-18.md)**

---

## 它到底解决什么问题

"突然变高延迟"至少有五种互不相干的原因，在浏览器里看起来完全一样：

1. 无线路由把客户端按在了弱/拥塞的 2.4 GHz 信道上（协商速率掉到 6.5 Mbps）；
2. 网卡驱动反复评估邻居 AP，却迟迟不肯离开那个烂 AP；
3. 本地代理 / VPN 客户端的上游劣化；
4. 后台进程把上行打满，AP 上出现缓冲膨胀；
5. 校园网 / 运营商的上联真的拥塞了。

单条 `ping` 分不开这些，因为"全都慢"是共同表现。能分开它们的是**哪一层先崩，以及同一秒还有什么东西在变**。

本工具把这些全部记在同一个时钟上，所以报告能说出这样的话：*"00:27:22，七个目标（含本地网关）同时返回同一个 2128 ms"* —— 这只可能是报文在**本机**被积压，而不是上游丢包。

## 和普通 ping 监控的区别

| 常见监控 | 本工具 |
|---|---|
| 60 秒 ping 一个地址 | 7 个目标跨 3 层，1 Hz；触发时 0.25 Hz 加密 |
| 不看无线 | 每 5 秒记录 BSSID / 频段 / 信道 / 协商速率 |
| 不看系统 | 关联 Intel `Netwtw*` + `WLAN-AutoConfig` + `NDIS` + `DHCP` 事件 |
| 没有退出条件 | 时长上限、数据上限、抓包上限——一定会自己结束 |
| 只给一张图 | 给出异常时间窗、逐窗口伴随证据、以及逐条"被支持/被否定"的假设表 |
| 一直挂着 | 有界会话，只保留最近 N 次，其余自动删除 |

## 运行条件

- Windows 10 / 11，**Windows PowerShell 5.1**（系统自带，不需要装 PowerShell 7）
- 只有可选的抓包（`pktmon`）需要管理员权限；其余全部只读，普通用户也能跑
- 最多约 400 MB 空闲磁盘（默认 300 MB 文本上限 + 64 MB 抓包环形缓冲）

## 快速开始

```powershell
# 1. 环境自检：权限、pktmon、事件日志、WLAN 读取
.\Run-Check.cmd

# 2. 卡的时候启动采集
.\Run-NetWatch.cmd
```

或者直接在 PowerShell 里：

```powershell
.\scripts\NetWatch.ps1                 # 默认 20 分钟
.\scripts\NetWatch.ps1 -Minutes 40     # 更长的窗口
.\scripts\NetWatch.ps1 -Quick          # 5 分钟自检
.\scripts\NetWatch.ps1 -NoPktmon       # 完全不抓包
```

`.cmd` 已经带了 `-ExecutionPolicy Bypass`，不会被脚本执行策略拦住。

### 异常刚刚过去怎么办

```powershell
.\Run-Forensics.cmd
```

回溯最近 **6 小时**的相关事件日志 + 立刻抓一次现场快照 + 采集 3 分钟，然后出报告。适合"事后才想起来"的场景。

### 运行时可以按的键

| 键 | 作用 |
|---|---|
| `M` | 打一个时间标记（"就是现在开始卡的"） |
| `S` | 立刻抓一次完整快照 |
| `E` | 延长 5 分钟（仍受 `MaxDurationMinutes` 约束） |
| `Q` | 立即结束并出报告 |
| `Ctrl+C` | 同 `Q`，会话会干净收尾 |

## 采集内容

| 模块 | 内容 | 默认频率 |
|---|---|---|
| 分层 ICMP | 网关 / 内网 DNS / 3 个公网 IPv4 / 1 个公网 IPv6 —— RTT、状态、TTL、源地址 | 1 秒（触发时 0.25 秒） |
| 无线链路 | `netsh wlan show interfaces` → 状态、SSID、**BSSID**、频段、信道、协议、RSSI、信号%、收发协商速率、网关 MAC | 5 秒 |
| 邻近 AP | 同 SSID 的所有 BSSID + 信号强度（用来发现"更好的 AP 明明在旁边"） | 120 秒 |
| 事件日志 | `Netwtw*`、`WLAN-AutoConfig`、`NDIS`、`TCPIP`、`Dhcp-Client`、`Kernel-Power`，连原始事件载荷一起存 | 5 秒 |
| TCP / 系统 | 重传率、连接失败/重置、TIME_WAIT、CPU、内存、磁盘队列、网卡字节速率、丢包与错误 | 10 秒 |
| 进程 | 按 PID 聚合的 TCP 连接数与总 IO（Top 15） | 15 秒 |
| DNS | 每个服务器 × 每个域名的解析耗时（在子运行空间里，绝不阻塞主循环） | 15 秒 |
| 代理对照 | 系统代理状态、端口存活、同一 URL 分别"经代理"和"直连"计时 | 30 秒 |
| 抓包 | `pktmon`，每包截断 96 字节，环形缓冲，只抓无线网卡 | 全程 |

## 硬性上限（不会失控）

| 限制项 | 默认值 | 行为 |
|---|---|---|
| 会话时长 | 20 分钟（硬上限 120） | 到点收尾出报告 |
| 文本数据（`data/`） | 300 MB | 超限立即收尾并标注"提前结束" |
| 抓包 | 64 MB 环形缓冲 | 写满覆盖最旧，物理封顶 |
| 磁盘可用 | 低于 3 GB | 拒绝启动 / 立即收尾 |
| 异常快照 | 每次会话 10 个，每个 40 MB | 超出只记标记 |
| 历史 | 最近 6 次 | 更旧的删除；全局 2 GB 上限 |

## 报告里有什么

`data\session-<时间戳>\report\`：

- **`report.md`** —— 人看最快的摘要
- **`report.html`** —— 同内容 + 4 张内联 SVG 曲线（RTT / RSSI / 吞吐 / 重传），异常窗口高亮，完全自包含
- **`summary.json`** —— 机器可读的紧凑指标
- **`evidence.zip`** —— 报告 + 全部 CSV 打成一个文件

章节顺序：会话信息 → 数据覆盖 → 分层延迟分布（min/p50/p95/p99/max/抖动/丢包）→ **异常时间窗与伴随证据**（RSSI、BSSID 切换、网关 MAC、吞吐峰值、CPU/磁盘、重传、命中的驱动事件）→ 无线链路层 → 本机资源 → 事件汇总 → 代理相位对照 → DNS → **逐条假设（被支持/被否定/未知）** → 文件清单。

## 最先要看的那个信号

如果**所有目标在同一瞬间返回同一个被抬高的 RTT**——连本地网关也一样——那报文根本没按时发出去。这是本机发送侧/空口排队（烂无线电、驱动队列、省电策略），不是上游问题。

脱敏后的真实例子：

```
00:27:22   gateway 2126 | local-dns 2128 | cloudflare 2128 | alidns 2128
           google-dns 2175 | quad9 2128 | cloudflare-v6 2128      ← 相互只差 2 ms
```

反过来，如果只有公网目标劣化、网关始终 4 ms，那瓶颈在上游，本地怎么调都没用。

检测规则与测量注意事项见 **[docs/how-it-works.md](docs/how-it-works.md)**。

## 报告之后常见的修复

如果报告显示客户端卡在一个低协商速率的 2.4 GHz AP 上，而同 SSID 的 5 GHz AP 一直可见且更强，第一个该改的就是网卡的频段偏好：

```powershell
.\scripts\Set-WifiBand.ps1 -Show      # 看当前值
.\scripts\Set-WifiBand.ps1            # 首选 5 GHz + 漫游中高
.\scripts\Set-WifiBand.ps1 -Revert    # 回退驱动默认
```

只改两个 Intel 驱动高级属性（`RoamingPreferredBandType`、`RoamAggressiveness`），可回退，重装驱动即恢复默认。

## 配置

把 `config.example.json` 复制成 `config.json` 再改，所有键都可省略。
`IcmpTargets` 里 `host` 留空表示运行时自动填充（`gateway` 用默认网关，`local-dns` 用本机 DNS）。
`ProxyPort: 0` 表示从系统代理设置里自动读端口。

命令行参数优先于配置文件：`-Minutes`、`-MaxMinutes`、`-Label`、`-LookbackHours`、
`-ForceSnapshot`、`-NoPktmon`、`-NoNeighborScan`、`-NoProxyProbe`、`-NoL7`、
`-NoEvents`、`-NoProc`、`-NoReport`、`-OpenReport`、`-CheckOnly`、`-StopPktmon`、
`-StartDelaySec`、`-ConfigPath`、`-DataRoot`、`-ReportRoot`。

## 安全与隐私

- **默认全只读**：ICMP、DNS 查询、HTTPS 请求、性能计数器、`Get-WinEvent`、
  `netsh wlan show *`、`ipconfig/arp/route/netstat`、只读读取 `HKCU` 的代理状态。
- **不改任何配置**，除非你自己显式执行 `Set-WifiBand.ps1`。不动防火墙、DNS、代理、电源计划、注册表。
- **唯一需要提权的动作**是可选抓包。`pktmon` 是 Windows 内置诊断工具：加载 PktMon 过滤驱动，被动复制报文，不修改、不阻断、不注入。文件写在本仓库自己的 `data/` 下。没有管理员权限就跳过抓包，其余照常。`-NoPktmon` 可彻底关闭。
- **不上传任何东西**：没有遥测、没有统计、没有外发。
- **数据只留在本地**：`data/`、`reports/`、`config.json` 和抓包文件都在 `.gitignore` 里。**永远不要公开自己的抓包**——那是你自己的流量。
- 邻近 AP 扫描（`netsh wlan show networks`）会触发一次主动扫描，可能造成亚毫秒级干扰。程序会记录扫描窗口，报告里会标注重叠；`-NoNeighborScan` 可关闭。

**绝对不要提交一次真实的采集结果。** `.pcapng` 里包含 DNS 查询、TLS SNI 和未加密的 HTTP 内容。
`tools/check-no-sensitive.ps1` 会阻止会话数据、抓包文件、私有 IP 和 MAC 被暂存——每次提交前跑一遍。

## 已知限制

- 报告是中文的（脚本、配置键、CSV 表头是英文/ASCII，数据本身与语言无关）。欢迎 PR 增加英文输出，字符串集中在 `scripts/NetWatch.Report.ps1`。
- 只能观察一台主机，看不到 AP 内部、看不到运营商、看不到别的设备。
- 环形缓冲只保留最近的流量，报告里会写明覆盖范围。
- `pktmon etl2pcap` 默认不导出被丢弃的包（可用 `--drop-only` 单独导出）。
- Windows 不提供每进程网络字节数，进程表是"连接数 + 总 IO"的近似。
- DNS 与 L7 探测跑在子运行空间里；万一卡住，那一轮记为 `ABORTED-TIMEOUT`，不会拖死主循环。

## 仓库结构

```
├─ README.md / README.zh-CN.md
├─ LICENSE  CHANGELOG.md  .gitignore  .gitattributes
├─ config.example.json
├─ docs/
│  ├─ case-study-2026-10-18.md    真实案例（脱敏）
│  └─ how-it-works.md            检测规则与测量注意事项
├─ scripts/                       PowerShell 模块
├─ tools/
│  └─ check-no-sensitive.ps1
└─ Run-*.cmd                      双击入口
```

## 参与贡献

最有用的 bug 报告是**脱敏后的报告片段**。开 PR 之前请先跑：

```powershell
.\tools\check-no-sensitive.ps1     # 必须通过
```

所有 `.ps1` 必须保存为 **UTF-8 with BOM** —— 否则 PowerShell 5.1 会用 ANSI 代码页解码，
非 ASCII 字符串字面量会直接语法报错。

## 许可证

[MIT](LICENSE) © 2026 Micheal Zi
