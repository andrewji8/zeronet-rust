# zeronet-rust

**一句话**：用 Rust 重写 ZeroNet —— 继承它的"站点地址就是密钥"的内容寻址 + 加密签名范式，但补上 ZeroNet 长期缺失的 Kademlia DHT、正式加密传输层（Noise-XX），并消除 Python 全局 monkey-patch、gevent 隐式竞态、无类型系统这三个工程性弱点。

**小白友好度**：本文档假设你刚装好 Rust 工具链。跟着下面 4 个代码块敲，你就能看到 `create-site → publish → blake3 → download` 整条去中心化链路跑通。

---

## 一、与 ZeroNet 的差异

| 维度 | ZeroNet（Python） | zeronet-rust |
|---|---|---|
| 发现机制 | 依赖外部 Bittorrent tracker（`udp://tracker...`），**没有真实 DHT** | **Kademlia DHT**（Amino 参数，`k=20 α=10 β=3`，自发现，provider 可经 wire 传播） |
| 并发模型 | `gevent.monkey.patch_all()` 全局 patch，隐式竞态 | **tokio** 原生 async，零全局副作用 |
| 密码学 | Secp256k1 + SHA-512（C 扩展 `coincurve` 有 crash 风险） | 可选 **Ed25519 + BLAKE3**（快 3–5×），**同时完整兼容 Secp256k1** |
| 传输层 | `fakedomains` 随机 SNI（yahoo/amazon...）伪装 IP 反 DPI | **Noise-XX**（X25519 + HKDF + ChaCha20-Poly1305，前向保密 + 双向身份认证） |
| 类型系统 | 纯 Python 动态类型，1000 行巨类 | Rust 所有权 + 模块边界，编译期消除隐式共享 |
| 兼容性 | — | **可读 / 可写现有 ZeroNet 站点**（Secp256k1 双 SHA256 ECRECOVER + base58check） |

> 设计参照：Kademlia 参数取自 `libp2p/go-libp2p-kad-dht`（IPFS 的 Amino 调优值）；内容寻址范式参照 Dat/Hypercore（Ed25519 + Merkle）；ZeroNet 兼容层精确复刻 `CryptBitcoin.py` / `libsecp256k1message.py` / `util/Electrum.py` 的签名链路；加密传输层按 Noise 规范 rev34 §7.5 的 `XX` 模式实现（参考 `flynn/noise` 的 token 序列）。

---

## 二、安装

### 2.1 前置：Rust 工具链

需要 **stable Rust ≥ 1.75**（`edition = "2021"`，本仓库未用任何 nightly 特性）。

```powershell
# Windows PowerShell
winget install Rustlang.rustup
# 或 https://rustup.rs 下载 rustup-init.exe
rustup update stable
```

> **避坑**：Windows 编译 `rusqlite`（`bundled` 特性会内嵌 SQLite C 源码）需要 **Microsoft Visual C++ Build Tools**（MSVC 工具链）或 **clang-cl**。如果 `cargo build` 报 `linker 'link.exe' not found`，安装 Visual Studio Build Tools 后重启终端。

### 2.2 拉代码 + 编译

```powershell
git clone <repo-url> zeronet-rust
cd zeronet-rust
cargo build
```

产物在 `target\debug\zeronet-rs.exe`（Windows）/ `target/debug/zeronet-rs`（Linux/macOS）。

### 2.3 验证

```powershell
.\target\debug\zeronet-rs.exe help
```

应打印 5 个子命令的用法。

---

## 三、5 个子命令

### 3.1 `create-site` — 生成一对密钥

```powershell
.\target\debug\zeronet-rs.exe create-site
```

输出示例：

```
site address:  9f07ca60688c8a1b8b9237394c8aedaa54741b6b05af6a5a70573167ddf83260
private key:   67956af2671a95bd97652cb259a1da1c838539b66841bbb4e4740d6046f3a4f9
save the private key now - you will need it to sign the site!
```

**关键**：把 `private key` 那一行**保存到一个安全的地方**。
- 它是 32 字节 ed25519 私钥（hex 表示），丢了就再也无法用这个站点地址签名。
- 站点地址（`site address`）是公钥派生，**可以公开**；私钥绝对不能公开。

### 3.2 `publish` — 签名并发布一个站点

```powershell
# 1) 准备一个站点的目录（可以是任意普通文件夹）
mkdir mysite
echo "<html><body><h1>Hello from ZeroNet-Rust</h1></body></html>" > mysite\index.html
echo "body { background: #fff; }" > mysite\style.css

# 2) 用刚才 create-site 生成的私钥签名 + 自校验
.\target\debug\zeronet-rs.exe publish mysite --secret 67956af2671a95bd97652cb259a1da1c838539b66841bbb4e4740d6046f3a4f9
```

输出示例：

```
persisted:        mysite\storage.db
persisted:        mysite\manifest.json
site 9f07ca60... signed with 2 files; manifest self-verified
```

`publish` 做的事：

1. 递归收集 `mysite/` 下所有文件（**自动跳过 `manifest.json` / `storage.db` 等自身产物**，不会把发布结果再算进站点里，详见 §5 避坑 #4）。
2. 每个文件算 BLAKE3 哈希，检查 15 MB 块上限。
3. 用 ed25519 私钥签 112 字节的"signable block"（site_key + tree_hash + file_count + fork + modified + 24 字节保留区）。
4. 自校验签名（防止私钥/公钥不一致就报错）。
5. 落盘 `manifest.json`（人类可读）+ `storage.db`（SQLite 持久化）。

#### 3.2.1 `--announce`：把 provider 广播到网络

```powershell
# 单节点自验（provider 记录只落本地，其它节点还找不到）
.\target\debug\zeronet-rs.exe publish mysite --secret <SECRET> --announce --max-sec 5

# 真正广播：需要一个 --bootstrap 对端，且对端也跑着 node / publish --announce
.\target\debug\zeronet-rs.exe publish mysite --secret <SECRET> --announce \
    --listen 0.0.0.0:47300 --secure-listen 0.0.0.0:47301 \
    --bootstrap 127.0.0.1:47310 --secure-bootstrap 127.0.0.1:47311 \
    --max-sec 60
```

`--announce` 内部流程：起明文 RPC + Noise-XX 加密双端口 → 可选 bootstrap 对端 → 对本地 `ProvideStore` 写一条 provider 记录（`content_key = BLAKE3("site:" || hex(site_key))`）→ 经 `provide_over_wire` / `provide_over_wire_secure` 广播到每个已知对端 → 继续 serve `--max-sec` 秒。

> 没有对端时 `--announce` 会打印 `warning: no peers reachable yet; the provider record is only stored locally.`，**这是正常行为**，不是错误。

#### 3.2.2 `--wif`：ZeroNet 兼容签名

```powershell
.\target\debug\zeronet-rs.exe publish mysite --wif 5K9S6dVpufGnroRgFrT6wsKiz2mJRYsC73eWDmajaHserAp3F1C
```

要求 `mysite/content.json` 存在（ZeroNet 原生的站点元数据格式）。产物是 `mysite/content.signed.json`，可直接被 ZeroNet 节点读取（Secp256k1 ECRECOVER + base58check 双 SHA256 验签链路，已在 `content::compat` 跨语言验证）。

### 3.3 `node` — 起一个完整节点

```powershell
.\target\debug\zeronet-rs.exe node .zrs-node \
    --max-sec 30 \
    --listen 0.0.0.0:47300 --secure-listen 0.0.0.0:47301 \
    --bootstrap 127.0.0.1:47310 --secure-bootstrap 127.0.0.1:47311 \
    --api 0.0.0.0:8080
```

参数说明：

| 参数 | 默认 | 作用 |
|---|---|---|
| `[DIR]` | `.zrs-node` | 数据目录（放 `kad.db` / `storage.db` / `noise_identity.bin`） |
| `--max-sec N` | 15 | 节点跑多久（演示用；`0` 会立刻退出） |
| `--listen H:P` | 随机 loopback | 明文 RPC 监听地址 |
| `--secure-listen H:P` | 不起 | Noise-XX 加密 RPC 监听地址 |
| `--api H:P` | 不起 | axum HTTP/WS API |
| `--bootstrap H:P`（可重复） | — | 明文 bootstrap 对端，每 10s 重试 |
| `--secure-bootstrap H:P`（可重复） | — | 加密 bootstrap 对端 |

`noise_identity.bin` 是节点的 X25519 身份，**跨重启保持不变**，可以安全拷贝到备份。

### 3.4 `download` — 下载并校验

```powershell
# 先拿到期望哈希（两种方式）
.\target\debug\zeronet-rs.exe blake3 path\to\file        # 方式 1：本地有文件
# 方式 2：站点 manifest.json 里已经存了每个文件的 hash（32 字节 = 64 hex）

# 再用环境变量把期望哈希传给 download
$env:ZRS_EXPECTED_HASH = "80624ebc8de155d8a14d9dfa87d850764b173718cce2d841aa57144c60027429"
.\target\debug\zeronet-rs.exe download 127.0.0.1:47300 1SITEADDR index.html
```

`download` 走的是 `worker::DownloadEngine`：连对端 → 明文 `GetFile` RPC → base64 解码 → BLAKE3 校验 → 写盘。如果哈希不匹配，**文件不会落盘**。

> **注意**：`download` 默认走**明文**通道。加密通道（`worker::download_via_dht_secure`）已实现但暂不暴露到 CLI（下一步路线）。

### 3.5 `blake3` — 算一个文件的哈希

```powershell
.\target\debug\zeronet-rs.exe blake3 mysite\index.html
# 80624ebc8de155d8a14d9dfa87d850764b173718cce2d841aa57144c60027429
```

就是 `sha256sum` 的 BLAKE3 版。

---

## 四、全链路示例（小白照抄）

> 以下命令在 **一台 Windows 机器**上就能跑完，用两个进程模拟两个节点。

### 4.1 起两个节点（A 和 B），让它们互相发现

```powershell
# 终端 1：起 A
.\target\debug\zeronet-rs.exe node .nodeA \
    --max-sec 30 \
    --listen 127.0.0.1:47300 --secure-listen 127.0.0.1:47301 \
    --bootstrap 127.0.0.1:47310 --secure-bootstrap 127.0.0.1:47311

# 终端 2：起 B（对称）
.\target\debug\zeronet-rs.exe node .nodeB \
    --max-sec 30 \
    --listen 127.0.0.1:47310 --secure-listen 127.0.0.1:47311 \
    --bootstrap 127.0.0.1:47300 --secure-bootstrap 127.0.0.1:47301
```

等几秒，两个终端都会打印：

```
[sb0] secure bootstrap ok: kad-peer ... noise-id ... at 127.0.0.1:47301
[b0] bootstrap ok: learned peer ... at 127.0.0.1:47300
```

意味着两个节点**经明文 + 加密两条通道**都互相对齐了。

### 4.2 A 发布一个站点，B 下载它

```powershell
# A 准备站点
mkdir .site
echo "<h1>From A</h1>" > .site\index.html

# A 生成密钥（保留 private key 输出，例如 $secret = "6795..."）
.\target\debug\zeronet-rs.exe create-site

# A 签名 + 广播到 B
.\target\debug\zeronet-rs.exe publish .site --secret <SECRET> --announce \
    --listen 127.0.0.1:47300 --secure-listen 127.0.0.1:47301 \
    --bootstrap 127.0.0.1:47310 --secure-bootstrap 127.0.0.1:47311 \
    --max-sec 20
```

B 终端会看到 A 的 provider 记录（`FindProviders` 回复里带 A 的 peer id + 地址）。然后 B 可以：

```powershell
# B 算期望哈希（假设你本地也有一份 index.html，或者从 manifest.json 拿 hash 字段）
$env:ZRS_EXPECTED_HASH = .\target\debug\zeronet-rs.exe blake3 .site\index.html
.\target\debug\zeronet-rs.exe download 127.0.0.1:47300 1SITEADDR index.html
```

`download` 会连到 A 的明文端口（47300）取文件，BLAKE3 校验通过后才写盘到 `1SITEADDR\index.html`。

> 真正的全链路（DHT 发现 + 加密下载）在 `net/tests/secure_e2e.rs::secure_download_via_dht_full_chain` 里已经集成测试过了，跑 1 次 0.5 秒。

---

## 五、避坑指南（小白最容易踩）

### #1 PowerShell 编码（`…` 变乱码）

PowerShell 5.1 的 `Get-Content` / `Set-Content` **默认用系统 ANSI 码页**（中文系统是 GBK）读/写文件。任何含 `…`、中文注释、UTF-8 字节的内容都会被静默损坏。

**规则**：
- 改 Rust 源码用 .NET API：`[System.IO.File]::WriteAllText($path, $content, [System.Text.Encoding]::UTF8)`（注意是无 BOM 的 `UTF8`）。
- 不要拿 `Set-Content` 写 `.rs` 文件。
- 如果 PowerShell 控制台显示乱码（例如 `e` 显示成 `n`），**那是显示问题，不代表文件坏了**——用编译器（`cargo build`）判断真值。

### #2 `git commit -m` 里带 backtick（PowerShell 转义）

PowerShell 的 backtick 是转义符。`-m "fix \`path\`"` 这种写法会吃掉 backtick。

**规则**：多行 commit message 写到文件里，用 `git commit -F path`：

```powershell
# 把 message 写到 .msg
git commit -F .msg
```

### #3 端口冲突

`--listen 47300` 如果已经被占（上一次没 `kill` 干净、或其它程序用了 47300），`node` 会立刻 `failed to bind the inbound server` 退出。

**规则**：
- 用 `netstat -ano | findstr :47300` 看谁占着。
- 或者干脆不传 `--listen`，让它自动选 loopback 随机端口（输出里会显示）。

### #4 站点目录里别放发布产物

`publish` 会递归收集 `mysite/` 下所有文件。如果你把 `mysite` 当工作目录，反复 `publish` 几次，目录里会堆 `manifest.json` / `storage.db` / `content.signed.json`。**这些是发布输出，不该再被算进站点**（下次 publish 签名会把上次的产物也签进去，形成"自我嵌套"）。

`publish` 已经默认跳过 `PUBLISH_ARTIFACTS = ["manifest.json","storage.db","kad.db","content.signed.json","noise_identity.bin"]`。如果你想加入白名单，改 `src/publish.rs::PUBLISH_ARTIFACTS`。

### #5 密钥保存

`create-site` 输出 32 字节私钥（hex）。**没有任何备份机制**，丢了就永远无法用这个站点地址签名。建议：

- 生成后立即写到 `secrets/<site_address>.pem` 之类的文件，并纳入你平时的密钥管理流程。
- 不要把私钥 commit 进 git。
- 多机部署时，把同一份私钥分发到需要签名的节点（站点只有一把密钥，所有 provider 用同一把）。

### #6 `ZRS_EXPECTED_HASH` 必须是 64 个 hex 字符

`download` 校验时长度不是 64 直接 `exit(2)`。用 `blake3` 子命令或 `manifest.json` 里的 `files[].hash` 字段（已是 64 hex）取，**不要**自己手算 sha256。

### #7 15 MB 块上限

`merkle::MAX_BLOCK_SIZE = 15 * 1024 * 1024`（对齐 Hypercore）。单个文件 > 15 MB 时 `publish` 会报 `TooLarge`。想传大文件要么分片，要么改这个常量（不建议）。

### #8 跨语言验证脚本依赖 Python 3.11

`verify_rust_signed.py` 在开发工作区（不入仓库），需要本机 Python 3.11 + ZeroNet 源码 + `pip install base58`。CI 不跑这个脚本，只跑 Rust 侧的 52 个测试。

### #9 Windows CRLF vs LF

`.gitattributes` 里 `text=auto`，git 会在 checkout 时把 LF 自动变 CRLF。`git status` 看到的 `LF will be replaced by CRLF` 警告**是无害的**，不要手动改。

### #10 `cargo audit` 首跑要拉 advisory DB

CI 第一次跑 `cargo audit` 会从 GitHub 拉 `RustSec/advisory-db`（几百 MB），可能比其它 step 慢 30–60 秒。本地首跑同理。后续走 `D:\.cargo\advisory-db` 缓存。

---

## 六、目录结构

```
crates/
├── kad       Kademlia DHT 发现层：路由表(k-bucket+LRU+IP多样性)、查询状态机、SQLite 持久化(RtDb)、
│             provider、RT 刷新。参数对照 Amino。
├── content   内容寻址层：Ed25519+BLAKE3 Merkle manifest（原生），
│             以及完整的 ZeroNet 兼容层（Secp256k1 验签 + 签名器，Python JSON 精确序列化）
├── net       TCP 传输层：长度前缀帧、GetFile/握手 RPC、peer 客户端、
│             DHT 走线（provide/find_providers over wire + AddressBook + bootstrap），
│             以及 **Noise-XX 加密通道**（X25519 + HKDF + ChaCha20-Poly1305，正式反 DPI）
│             + DHT 走线的安全变体 find_providers_over_wire_secure（每个查询各走一次 Noise 握手）
├── storage   本地存储：站点目录、HashField 索引、store_verified(BLAKE3 校验+防路径穿越)、SQLite 持久化(Db)
├── worker    并发下载：TaskQueue、DownloadEngine(有界并发窗口)、download_and_store、
│             download_via_dht（发现 provider → 取文件 → 校验 → 落盘 全链路）
│             + download_via_dht_secure（同样全链路但走 Noise 加密通道）
└── api       axum HTTP/WS 路由：/status、/sites/{site}/{path}(防穿越)、/download(DHT 全链路)、/ws
src/main.rs   CLI 入口：node / create-site / publish / download / blake3 / help
src/publish.rs 站点发布逻辑：collect_files + build_site_manifest + site_content_key
```

---

## 七、测试与 CI

### 7.1 本地

```powershell
cargo fmt --all -- --check          # 格式（CI 也跑）
cargo clippy --workspace -- -D warnings   # lint（CI 也跑）
cargo test --workspace              # 52 tests
cargo audit                         # 供应链审计（CI 也跑）
```

### 7.2 CI（`.github/workflows/ci.yml`）

两个 job：

| job | 步骤 |
|---|---|
| `test` | `fmt --check` → `clippy -D warnings` → `build` → `test` |
| `security` | `cargo install cargo-audit` → `cargo audit`（154 个 lock 依赖对 RustSec DB） |

### 7.3 测试分布

| crate | 测试数 | 覆盖 |
|---|---|---|
| `kad` | 10 | `cpl`/`xor_distance` 距离度量、路由表 IP 多样性上限、`hash_key`、**路由表 SQLite 持久化 roundtrip** |
| `content` | 18 | BLAKE3 Merkle 回环、CPython `json.dumps` 逐字节 golden、ZeroNet 官方 ECRECOVER 向量、varint 双分支双 SHA256 golden、sign→recover 自回环 |
| `net` | 9 | loopback 服务 roundtrip、**双节点 DHT over TCP**（互发现 + provider 交换 + 发现→下载全链路）、**Noise-XX 加密 roundtrip + 身份绑定 + 篡改拒绝 + 加密全链路下载** |
| `worker` | 3 | loopback 真实下载（连接→GetFile→base64 解码→BLAKE3 校验→写盘）、拒绝错误哈希、批量并发 |
| `storage` | 2 | **HashField + SiteManifest SQLite 持久化 roundtrip** |
| `api` | 4 | `/status`、`/sites/{site}/{path}` 防路径穿越、`/download` 拒绝错误哈希 |
| 根 smoke | 1 | 双真实进程 `node --bootstrap` 组网（互学 peer + 落盘 `kad.db`） |
| bin 内测试 | 5 | `publish` 的 3 个单元 + 2 个集成（含 artifact-skip 回归） |

**合计 52 tests，0 警告，0 clippy lint，cargo audit 干净。**

### 7.4 跨语言验证（非循环自证）

`content` 的兼容性不是"Rust 签 Rust 验"，而是**两端独立实现互验**：

- **读**：ZeroNet 自带 `sslcrypto` 纯 Python secp256k1 引擎签出的 `content.json` → Rust `verify_zeronet_content` 通过（覆盖 342 字节长 varint 分支）。
- **写**：Rust `ZeronetKey::sign_content` 产出的 `content.json` → ZeroNet `sslcrypto` 引擎 recover 出正确地址（覆盖"Rust 发布的站点能被 ZeroNet 读"）。

参考脚本（需本机 Python 3.11 + ZeroNet 源码 + `pip install base58`）：`verify_rust_signed.py` / `probe_layout.py`（在开发工作区，不入仓库）。

---

## 八、Noise-XX 传输层（替代 ZeroNet fakedomains）

`net::secure` 按 Noise 规范 rev34 §7.5 的 `XX` 模式手工实现（X25519 + HKDF(HMAC-SHA256) + ChaCha20-Poly1305），取代 ZeroNet 用随机 SNI（yahoo/amazon…）伪装 IP 的 `fakedomains` 反 DPI hack：

- **前向保密**：每会话新临时密钥，长期 X25519 身份不进入会话密钥。
- **双向认证**：双方静态密钥互认，握手后各自拿到对端 `NoiseIdentity`（hex）。
- **AEAD 完整帧**：每个应用帧都是长度前缀的 ChaCha20-Poly1305 密文，篡改/错密钥/错 nonce 全部被拒。
- **可持久化身份**：`NoiseIdentity::load_or_new` 把 X25519 私钥落在 `noise_identity.bin`，重启不变。

XX 消息序列（spec §7.5）：

```text
c -> e
c <- e, ee, s, se
c -> s, se
```

测试：`aead_roundtrip_and_tamper_rejection`（密文≠明文 + 篡改/错钥/错 nonce 被拒）、`dh_is_symmetric`、`identity_save_load_roundtrip`（单元）；`secure_get_file_roundtrip`（加密取文件 + 身份绑定）、`handshake_mismatch_and_tamper_are_rejected`、`secure_download_via_dht_full_chain`（e2e）。

---

## 九、关键参数（对照 IPFS Amino DHT）

| 参数 | 默认 | 说明 |
|---|---|---|
| `bucket_size` (k) | 20 | 每个 k-bucket 最多 20 peer |
| `concurrency` (α) | 10 | 同波次并发查询数（`light_node()` preset 降为 8） |
| `resiliency` (β) | 3 | 最靠近目标 3 个 peer 全回复才结束 |
| `max_record_age` | 48h | value record 存活时间 |
| `reprovide_interval` | 22h | 定期重新 Provide |
| `rt_refresh_period` | 10min | 路由表刷新 |
| `max_peers_per_ip_group` | 3 | 同 /24 IP 组全表上限 |

---

## 十、路线图

- [x] 项目骨架（6 crates，编译 0 警告）
- [x] Kademlia 查询状态机 + 路由表（对照 `go-libp2p-kad-dht`）
- [x] 内容层：Ed25519+BLAKE3 原生 manifest + ZeroNet 兼容层（读）
- [x] ZeroNet 兼容层（写）：Secp256k1 可恢复签名器 + 跨语言验证
- [x] 真实下载通路：TCP + GetFile RPC + BLAKE3 校验 + 落盘 + loopback 集成测试
- [x] **SQLite 持久化（`rusqlite` bundled）：HashField + SiteManifest + 路由表 落盘，重启不丢索引**
- [x] `node` 子命令接通：tokio runtime + TCP 监听 + `--bootstrap` 多节点组网 + 持久化
- [x] **DHT 实际走线：`PutValue/FindProviders/GetClosestPeers` RPC 经 TCP（`net::dht`）**
- [x] **Noise-XX 加密传输层（X25519 + HKDF + ChaCha20-Poly1305）：`net::secure` + `--secure-listen/--secure-bootstrap`**
- [x] `api` 的 axum 路由：`/status`、`/sites/{site}/{path}`（路径穿越防护）、`/download`（DHT 全链路）、`/ws`
- [x] `worker` 接入 `find_providers`（`download_via_dht`），"发现→取文件→校验→落盘"全链路打通
- [x] **worker 切到 Noise 加密通道**：`net::dht::find_providers_over_wire_secure`（每个查询各走一次 Noise 握手）+ `worker::download_via_dht_secure`（`sec_get_file` 拉文件 + BLAKE3 校验落盘）；明文路径保留，新增 1 个 e2e 测试覆盖全链路
- [x] **site-publish CLI**：`create-site → 签名 content.json / manifest.json → 经 DHT announce provider`（`src/publish.rs` + `src/main.rs::publish`）
- [x] **生产就绪**：`cargo fmt --check` gate + `LICENSE`（MIT OR Apache-2.0）+ `cargo audit` 供应链审计 + 修掉全部 12 个 clippy lint

**全部路线图项已勾完。**

---

## 十一、许可

`MIT OR Apache-2.0`（`Cargo.toml` 里 `license = "MIT OR Apache-2.0"`，对应 `LICENSE` 文件）。
