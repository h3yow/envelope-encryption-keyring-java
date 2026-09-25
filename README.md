# 信封加密密钥环（Envelope Encryption Keyring, EEKR）

基于 Spring Boot 3 / Java 21 的**可本地运行**密钥分层加密与轮换能力。用本地文件持久化模拟密钥环（Keyring），
在多入口（加密 / 解密 / 轮换 / 重包裹）与并发条件下保证结论一致、可审计、可恢复。

- 每次加密生成**独立的一次性数据密钥（DEK）**，DEK 由主密钥（KEK）做信封包裹；
- 主密钥支持生成、启停与**有序轮换**，密文头携带可解析的密钥版本线索；
- 支持历史密文**重包裹（re-wrap）迁移**，迁移前后明文与 DEK 语义不变；
- 同一迁移请求重复提交**幂等**；并发下无半迁移、无重复处理；
- 管理操作与业务操作有明确**权限边界**；错误原因**可区分**，底层密码学异常不对外透出。

---

## 1. 密钥分层与权限边界

### 1.1 三层密钥模型

| 层级 | 密钥 | 来源 | 是否落盘 | 用途 |
|---|---|---|---|---|
| 根密钥（Root Key） | 256 bit | 由配置口令 `eekr.root-key-passphrase` 经 **PBKDF2-HMAC-SHA256** + 随机盐派生 | 口令与根密钥均**不落盘**，盐随密钥环保存 | 包裹/解包主密钥材料 |
| 主密钥（KEK） | 256 bit，AES | `SecureRandom` 生成，版本 `v1`,`v2`,…单调递增 | **仅以根密钥 AES-GCM 包裹后的密文**落盘 | 包裹数据密钥 |
| 数据密钥（DEK） | 256 bit，AES | 每次加密独立随机生成 | 不落盘，仅以“被当前 KEK 包裹”的形式存在于密文中 | 加密业务明文 |

所有对称运算均为 **AES-256-GCM**（IV 96bit 随机，Tag 128bit）。

### 1.2 角色与接口边界

| 接口 | USER 令牌 | ADMIN 令牌 |
|---|---|---|
| `POST /api/v1/encrypt` | ✅ | ✅ |
| `POST /api/v1/decrypt` | ✅ | ✅ |
| `POST /api/v1/rewrap` | ✅（含对**已停用**源版本的维护式迁移） | ✅ |
| `GET  /api/v1/admin/keys` | ❌ | ✅ |
| `POST /api/v1/admin/keys/rotate` | ❌ | ✅ |
| `POST /api/v1/admin/keys/{version}/disable` | ❌ | ✅ |

- 令牌经 `Authorization: Bearer <token>`（或裸令牌）提交，常量时间比较。
- 鉴权失败统一为 `403 UNAUTHORIZED`；错误响应只含固定文案与令牌 SHA-256 前缀（仅服务端日志），
  **不含令牌、口令、密钥材料**。
- 密钥列表视图只含 `version/status/current/createdAt`，不含任何材料字段。

### 1.3 审计日志

关键判定均以 INFO/WARN 落日志，且只记录**摘要**，不记录原文与密钥：
输入/上下文 SHA-256 前缀、密钥版本、判定依据（`basis=`），例如
`decrypt denied: keyVersion=v1 basis=context-hash-mismatch`。

---

## 2. 密文格式与版本兼容

### 2.1 信封二进制结构（Base64 对外传输）

```
magic      "EEKR"            # 魔数
format     1 字节             # 格式版本，当前 = 1
kvLen/keyVersion              # 密钥版本线索（UTF-8，如 v3）——解密时据此定位 KEK
ctxHash    32 字节            # 约定上下文的 SHA-256
wkIv       12 字节            # 包裹 DEK 的 IV
wkLen/wrappedKey              # 被 KEK 加密的 DEK（含 GCM tag），AAD = "WK"||keyVersion||ctxHash
dIv        12 字节            # 数据加密 IV
ctLen/ciphertext              # 业务密文（含 GCM tag），AAD = "DT"||ctxHash
```

约定 `context` 同时参与两段 GCM 的 AAD，实现上下文绑定。

### 2.2 解密判定顺序（错误原因可区分）

| 顺序 | 判定 | 错误码 | HTTP |
|---|---|---|---|
| 1 | Base64 / 魔数 / 格式版本 / 长度 / 版本字段缺失 | `CIPHERTEXT_MALFORMED` | 400 |
| 2 | 密文头版本在密钥环中不存在 | `KEY_VERSION_UNKNOWN` | 409 |
| 2 | 该版本已被停用（`decrypt` 拒绝） | `KEY_VERSION_DISABLED` | 409 |
| 3 | 上下文 SHA-256 不一致（先于密码学运算判定） | `CONTEXT_MISMATCH` | 422 |
| 4 | 包裹 DEK 的 GCM tag 校验失败 | `CIPHERTEXT_TAMPERED` | 422 |
| 4 | 数据密文的 GCM tag 校验失败 | `CIPHERTEXT_TAMPERED` | 422 |

底层 `AEADBadTagException` 等只作为 cause 进入服务端日志，对外统一固定文案；
不存在“用错误密钥解密出乱码”的分支——认证失败即拒绝。

### 2.3 轮换与版本兼容规则

- **有序轮换**：写锁串行化，计数器单调递增（v1→v2→…），无重复、无空洞。
  轮换 = 生成新版本并原子落盘 → 切换 `current` 指针；**旧版本保持 ENABLED**，历史密文持续可解密。
- **加密永远走 `current` 版本**；**解密按密文头版本**取对应 KEK。
- **停用**只影响“用该版本解密”；当前 `current` 版本禁止停用（需先轮换）；重复停用幂等。
- 未知 / 已停用版本的解密请求被拒绝，原因分别为 `KEY_VERSION_UNKNOWN` / `KEY_VERSION_DISABLED`。
- 首次启动在空密钥环上自动引导 `v1`；密钥环文件损坏时**拒绝静默重建**（否则历史数据将永久不可解密）。

### 2.4 重包裹迁移规则

- 仅更换“包裹 DEK 的 KEK 版本、包裹 IV、包裹密文”和密文头版本线索；
  **DEK 字节、数据 IV、数据密文段原样保留**，因此迁移前后明文语义严格一致。
- 源版本已经是 `current` → no-op，原样返回。
- **已停用的源版本允许作为迁移源**（但不允许直接解密），用于把历史数据搬到新版本后恢复可读。
- 幂等：
  - `requestId` 相同且输入摘要相同 → 返回首次结果，`replayed=true`；
  - `requestId` 相同但输入（密文+上下文）摘要不同 → `400 IDEMPOTENCY_CONFLICT`；
  - 幂等记录每请求一个文件，原子写入，**重启后仍然生效**。
- 并发安全：密钥环一把 `ReentrantReadWriteLock`（读：加解密/重包裹，写：轮换/停用），
  状态“先改内存、提交点原子落盘、成功后才可见”；重包裹在一次调用内取版本快照，
  与轮换交叉也只会得到“旧版本可解 / 新版本可解”的可解释结果，无半迁移中间态。

---

## 3. 本地持久化

默认目录 `${user.home}/.eekr`：

```
~/.eekr/
├── keyring.json                 # KDF 盐、版本计数器、current、各版本被包裹的 KEK（无明文）
└── rewraps/
    └── rewrap-<requestId>.json  # 幂等记录（输入摘要、输出密文、输出版本）
```

- 写入采用 `临时文件 + 原子 move`，POSIX 下密钥环文件权限收紧为 `0600`。
- 根密钥口令不持久化；更换口令会导致既有主密钥无法解包（本地演练时保持一致即可）。

---

## 4. 配置项语义（`src/main/resources/application.properties`）

| 配置项 | 含义 | 默认（开发） |
|---|---|---|
| `eekr.data-dir` | 本地持久化目录 | `~/.eekr` |
| `eekr.root-key-passphrase` | 根密钥口令，PBKDF2 输入，不落盘 | `local-dev-passphrase-change-me` |
| `eekr.kdf-iterations` | PBKDF2 迭代次数 | `120000` |
| `eekr.admin-token` | 管理令牌（轮换/停用/列表） | `admin-token-dev` |
| `eekr.user-token` | 业务令牌（加解密/重包裹） | `user-token-dev` |
| `eekr.idempotency.max-records` | 幂等记录内存缓存上限（磁盘记录不受影响） | `10000` |

> 以上令牌/口令仅用于本地模拟，生产应替换为外部密钥管理与真实认证体系。

---

## 5. 本地验证方法

### 5.1 构建与测试

```bash
mvn test          # 33 个测试：原语/格式、密钥环、加解密、重包裹、鉴权、并发、Web 端到端
mvn spring-boot:run   # 启动，监听 :8080
```

测试覆盖：并发轮换+重包裹+解密一致性、同 requestId 并发只有一次真实迁移、
密文篡改、上下文不匹配、停用密钥、未知版本、未授权操作、重启恢复；
断言错误码可区分、状态可恢复，测试日志打印输入摘要、密钥版本与 `basis` 判定依据。

### 5.2 curl 演练

```bash
A="Authorization: Bearer admin-token-dev"
U="Authorization: Bearer user-token-dev"
J="Content-Type: application/json"
B=http://localhost:8080

# 加密 / 解密
CT=$(curl -s -X POST $B/api/v1/encrypt -H "$U" -H "$J" \
  -d '{"plaintext":"hello","context":"tenant-1"}' | tee /tmp/enc.json | jq -r .ciphertext)
curl -s -X POST $B/api/v1/decrypt -H "$U" -H "$J" \
  -d "{\"ciphertext\":\"$CT\",\"context\":\"tenant-1\"}"

# 轮换（仅 ADMIN）后停用旧版本
curl -s -X POST "$B/api/v1/admin/keys/rotate?reason=policy" -H "$A"
curl -s -X POST $B/api/v1/admin/keys/v1/disable -H "$A"

# 历史密文迁移到新版本（USER 可发起），重复提交 replayed=true
curl -s -X POST $B/api/v1/rewrap -H "$U" -H "$J" \
  -d "{\"ciphertext\":\"$CT\",\"context\":\"tenant-1\",\"requestId\":\"rid-1\"}"
```

### 5.3 可观察的错误响应示例

```json
{"errorCode":"CONTEXT_MISMATCH","message":"encryption context does not match","timestamp":"..."}
{"errorCode":"CIPHERTEXT_TAMPERED","message":"data ciphertext authentication failed","timestamp":"..."}
{"errorCode":"KEY_VERSION_DISABLED","message":"key version disabled: v1","timestamp":"..."}
{"errorCode":"UNAUTHORIZED","message":"admin privilege required for key management operations","timestamp":"..."}
```

---

## 6. 代码结构

```
crypto/    CryptoService(AES-GCM/PBKDF2) EnvelopeFormat(密文结构) ErrorCode CryptoException DigestUtil
keyring/   KeyRing(锁/轮换/启停/缓存) FileKeyStore KeyRingState MasterKeyRecord KeyStatus
auth/      AuthService(令牌与角色) Caller AccessDeniedException
service/   EncryptionService KeyAdminService RewrapService IdempotencyStore + dto
web/       EncryptController KeyAdminController GlobalExceptionHandler
config/    AppConfig EekrProperties
```
