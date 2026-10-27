# zeronet-rust

Rust 实现的去中心化加密站点网络，目标是**继承 ZeroNet 的内容寻址 + 加密签名范式**（站点地址 = 密钥），同时补齐 ZeroNet 长期缺失的能力，并消除其工程性弱点。

与 ZeroNet（Python + gevent）相比：

| 维度 | ZeroNet | zeronet-rust |
|---|---|---|
| 发现机制 | 依赖外部 tracker（`udp://tracker...`），无真实 DHT | **Kademlia DHT**（Amino 参数，`k=20 α=10 β=3`，自发现，可经 wire 传播 provider） |
| 并发模型 | `gevent.monkey.patch_all()` 全局 patch，隐式竞态 | **tokio**，无全局副作用 |
| 密码学 | Secp256k1 + SHA-512（C 扩展 `coincurve` 有 crash 风险） | 可选 **Ed25519 + BLAKE3**（快 3–5×），**同时完整兼容 Secp256k1** |
| 传输层 | `fakedomains` 随机 SNI 反 DPI（伪 IP） | **Noise-XX**（X25519 + HKDF + ChaCha20-Poly1305，前向保密 + 双向身份认证） |
| 类型系统 | 纯 Python 动态类型，1000 行巨类 | Rust 所有权 + 模块边界，编译期消除隐式共享 |
| 兼容性 | — | **可读 / 可写现有 ZeroNet 站点**（Secp256k1 双 SHA256 ECRECOVER + base58check） |

> 设计参照：Kademlia 参数取自 `libp2p/go-libp2p-kad-dht`（IPFS 的 Amino 调优值）；
> 内容寻址范式参照 Dat/Hypercore（Ed25519 + Merkle）；ZeroNet 兼容层精确复刻
> `CryptBitcoin.py` / `libsecp256k1message.py` / `util/Electrum.py` 的签名链路；
> 加密传输层按 Noise 规范 rev34 §7.5 的 `XX` 模式实现（参考 `flynn/noise` 的 token 序列）。

## 目录结构

```
crates/
├── kad       Kademlia DHT 发现层：路由表(k-bucket+LRU+IP多样性)、查询状态机、SQLite 持久化(RtDb)、
│             provider、RT 刷新。参数对照 Amino。
├── content   内容寻址层：Ed25519+BLAKE3 Merkle manifest（原生），
│             以及完整的 ZeroNet 兼容层（Secp256k1 验签 + 签名器，Python JSON 精确序列化）
├── net       TCP 传输层：长度前缀帧、GetFile/握手 RPC、peer 客户端、
│             DHT 走线（provide/find_providers over wire + AddressBook + bootstrap），
│             以及 **Noise-XX 加密通道**（X25519 + HKDF + ChaCha20-Poly1305，正式反 DPI）
├── storage   本地存储：站点目录、HashField 索引、store_verified(BLAKE3 校验+防路径穿越)、SQLite 持久化(Db)
├── worker    并发下载：TaskQueue、DownloadEngine(有界并发窗口)、download_and_store、
│             download_via_dht（发现 provider → 取文件 → 校验 → 落盘 全链路）
└── api       axum HTTP/WS 路由：/status、/sites/{site}/{path}(防穿越)、/download(DHT 全链路)、/ws
src/main.rs   CLI 入口：node(含 --secure-listen/--secure-bootstrap) / create-site / download / help
```

## 快速开始

```bash
cargo build

# 生成一个站点密钥对（ZeroNet 风格，可发布/签名）
./target/debug/zeronet-rs create-site

# 起一个节点：明文 + 加密(RPC 走 Noise-XX)双端口，互相 bootstrap
./target/debug/zeronet-rs node .zrs-node \
    --listen 127.0.0.1:47300 --secure-listen 127.0.0.1:47301 \
    --bootstrap 127.0.0.1:47310 --secure-bootstrap 127.0.0.1:47311

# 从 peer 下载一个文件（BLAKE3 校验后写入 ./<site>/<path>）
#   需先通过 DHT/manifest 取得该文件的 BLAKE3 哈希
ZRS_EXPECTED_HASH=<64-hex blake3> ./target/debug/zeronet-rs download 127.0.0.1:PORT 1SITEADDR index.html
```

`node` 子命令是完整可运行节点：起 Kademlia + 明文/加密双 RPC 服务 + SQLite 持久化 + 可选 axum API，
`--bootstrap` / `--secure-bootstrap` 会对称连接对端（并每 10s 重试直至 `--max-sec`）。
加密端口上所有 RPC 都包在 Noise-XX 通道里，X25519 身份持久化在 `noise_identity.bin`。

## 测试

```bash
cargo test          # 46 tests 全绿（含 axum API 4 + Noise-XX 5 + 双进程 bootstrap 冒烟 1 + 双进程 secure 冒烟）
```

| crate | 测试数 | 覆盖 |
|---|---|---|
| `kad` | 10 | `cpl`/`xor_distance` 距离度量、路由表 IP 多样性上限、`hash_key`、**路由表 SQLite 持久化 roundtrip** |
| `content` | 18 | BLAKE3 Merkle 回环、CPython `json.dumps` 逐字节 golden、ZeroNet 官方 ECRECOVER 向量、varint 双分支双 SHA256 golden、sign→recover 自回环 |
| `net` | 8 | loopback 服务 roundtrip、**双节点 DHT over TCP**（互发现 + provider 交换 + 发现→下载全链路）、**Noise-XX 加密 roundtrip + 身份绑定 + 篡改拒绝** |
| `worker` | 3 | loopback 真实下载（连接→GetFile→base64 解码→BLAKE3 校验→写盘）、拒绝错误哈希、批量并发 |
| `storage` | 2 | **HashField + SiteManifest SQLite 持久化 roundtrip** |
| `api` | 4 | `/status`、`/sites/{site}/{path}` 防路径穿越、`/download` 拒绝错误哈希 |
| 根 smoke | 1 | 双真实进程 `node --bootstrap` 组网（互学 peer + 落盘 `kad.db`） |

### 跨语言验证（非循环自证）

`content` 的兼容性不是"Rust 签 Rust 验"，而是**两端独立实现互验**：

- **读**：ZeroNet 自带 `sslcrypto` 纯 Python secp256k1 引擎签出的 `content.json` → Rust `verify_zeronet_content` 通过（覆盖 342 字节长 varint 分支）。
- **写**：Rust `ZeronetKey::sign_content` 产出的 `content.json` → ZeroNet `sslcrypto` 引擎 recover 出正确地址（覆盖"Rust 发布的站点能被 ZeroNet 读"）。

参考脚本（需本机 Python 3.11 + ZeroNet 源码 + `pip install base58`）：
`verify_rust_signed.py` / `probe_layout.py`（在开发工作区，不入仓库）。

### Noise-XX 传输层（替代 ZeroNet fakedomains）

`net::secure` 按 Noise 规范 rev34 §7.5 的 `XX` 模式手工实现（X25519 + HKDF(HMAC-SHA256) + ChaCha20-Poly1305），
取代 ZeroNet 用随机 SNI（yahoo/amazon…）伪装 IP 的 `fakedomains` 反 DPI hack：

- **前向保密**：每会话新临时密钥，长期 X25519 身份不进入会话密钥。
- **双向认证**：双方静态密钥互认，握手后各自拿到对端 `NoiseIdentity`（hex）。
- **AEAD 完整帧**：每个应用帧都是长度前缀的 ChaCha20-Poly1305 密文，篡改/错密钥/错 nonce 全部被拒。
- **可持久化身份**：`NoiseIdentity::load_or_new` 把 X25519 私钥落在 `noise_identity.bin`，重启不变。

测试：`aead_roundtrip_and_tamper_rejection`（密文≠明文 + 篡改/错钥/错 nonce 被拒）、
`dh_is_symmetric`、`identity_save_load_roundtrip`（单元）；
`secure_get_file_roundtrip`（加密取文件 + 身份绑定）、`handshake_mismatch_and_tamper_are_rejected`（e2e）。

## 关键参数（对照 IPFS Amino DHT）

| 参数 | 默认 | 说明 |
|---|---|---|
| `bucket_size` (k) | 20 | 每个 k-bucket 最多 20 peer |
| `concurrency` (α) | 10 | 同波次并发查询数（`light_node()` preset 降为 8） |
| `resiliency` (β) | 3 | 最靠近目标 3 个 peer 全回复才结束 |
| `max_record_age` | 48h | value record 存活时间 |
| `reprovide_interval` | 22h | 定期重新 Provide |
| `rt_refresh_period` | 10min | 路由表刷新 |
| `max_peers_per_ip_group` | 3 | 同 /24 IP 组全表上限 |

## 路线图

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
- [ ] 把 `worker` 的下载/`find_providers` 也切到加密通道（当前 worker 仍走明文 `get_file`）
- [ ] site-publish CLI（create-site → 签名 content.json → 经 DHT announce provider）

## 许可证

MIT OR Apache-2.0
