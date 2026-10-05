# Envelope Encryption Keyring (Java / Spring Boot)

本地可运行的密钥分层加密与轮换服务：以本地持久化文件模拟密钥环，提供信封加解密、
主密钥有序轮换、按请求幂等的历史密文重包裹迁移，并在多入口（REST / 服务层）与并发条件下
保证结论一致、可审计。密钥环落盘由根口令包裹保护，文件本身不含任何明文密钥材料。

## 1. 密钥分层与权限边界

```
根口令（本地配置 keyring.root-key，PBKDF2 派生根密钥，只用于包裹 KEK，不落盘）
 └─ 包裹 → KEK（主密钥，密钥环内按版本管理，keyring.json 以包裹形态持久化）
       └─ 包裹 → DEK（数据密钥，每次加密随机生成，随密文携带）
             └─ 加密 → 业务明文（AES-256-GCM，约定上下文作为 AAD）
```

- **加密**：每次生成独立 256 位 DEK，用当前活跃 KEK 以 AES-GCM 包裹；
  明文用 DEK 以 AES-GCM 加密，约定上下文（context）作为附加认证数据（AAD）。
- **密文格式**（单行七段，携带可解析的密钥版本线索）：
  `EK1.<kekVersion>.<b64 wrapIv>.<b64 wrappedDek>.<b64 dataIv>.<b64 ciphertext>.<b64 contextTag>`
  - `contextTag` = HMAC-SHA256(DEK, context) 截断 16 字节，用于把“上下文不匹配”与“密文篡改”区分为不同错误。
- **权限边界**：
  - 管理操作（轮换 `/api/admin/keys/rotate`、停用 `/api/admin/keys/disable`）必须携带
    `X-Admin-Token` 头，令牌以常量时间比对；鉴权失败返回 `403 UNAUTHORIZED_OPERATION`，
    不泄露令牌或任何密钥材料。
  - 普通加解密调用方（`/api/crypto/*`）与迁移调用方（`/api/migration/rewrap`）无法触发轮换或停用。
- **审计**：所有关键操作以 `AUDIT action=... kekVersion=... result=... reason=...` 形式落日志，
  只记录版本号、请求编号、指纹前缀与判定依据，绝不记录密钥材料、根口令或密文全文。

## 2. 密钥环落盘保护与旧格式升级

- **落盘保护（格式 v2）**：每个主密钥材料用根口令派生的根密钥（PBKDF2-HmacSHA256，
  随机盐 + 210000 次迭代）以 AES-256-GCM 单独包裹后落盘。文件中只有
  `wrappedMaterialBase64` / `wrapIvBase64` 与 KDF 参数（盐、迭代次数不是秘密），
  光看文件读不出任何密钥材料。
- **旧格式升级（格式 v1 → v2）**：旧格式文件（明文 `materialBase64`、无 `formatVersion`）
  仍可正常加载；加载成功后立即以 v2 重新落盘完成平滑升级。升级只改变落盘形态，
  不改变任何密钥材料，因此**升级前发出的密文照样能解，轮换继续有序递增，迁移结论不变**。
- **根口令缺失/错误**：
  - `keyring.root-key` 为空（未配置）→ 拒绝启动，绝不退化为明文加载或明文落盘；
  - 根口令与落盘文件不匹配 → 启动失败并抛出 `KEY_RING_UNLOCK`，
    异常消息与日志不含口令或密钥材料；
  - 旧格式文件 + 未配置根口令 → 同样拒绝，文件保持原样不被改写。

## 3. 按请求幂等的迁移

调用方每次发起迁移必须携带自己生成的**请求编号**（`requestId`）：

- **同号 + 相同输入**：真实迁移只发生一次。无论并发同时打到服务上，还是服务重启后再次提交，
  后续请求一律**重放**首次结果：返回与首次一模一样的密文，且响应中 `replayed=true`，
  调用方能明确看出这是重放、不是又迁了一遍。
- **同号 + 不同输入**：拒绝并返回 `409 MIGRATION_CONFLICT`，与密文损坏
  （`CIPHERTEXT_INTEGRITY`）、版本不对（`UNKNOWN_KEY_VERSION`）、上下文不匹配
  （`CONTEXT_MISMATCH`）等其它失败明确区分。冲突判定基于输入指纹
  SHA-256(context ‖ 0x00 ‖ envelope)，服务不依赖密文内容之外的任何调用方声明。
- **恰好一次（并发）**：同一编号的并发请求里只有第一个执行真实迁移，其余等待同一结果并标记
  为重放，各次返回的密文一致。
- **失败不记录**：迁移失败（如密文被篡改）不会写入记录，同一编号修正输入后可正常重试。
- **记录上限与淘汰**：记录持久化在 `keyring.migration-records-path`，上限由
  `keyring.migration-max-records` 控制；超过上限后按 **FIFO 淘汰最旧记录**（确定性规则）。
  淘汰后最近提交过的请求仍能正常重放；已被淘汰的编号再次提交时按新请求处理（重新迁移）。
- **可审计**：每次判定都落日志
  `AUDIT action=migrate requestId=... fingerprint=<前12位> decision=migrated|replayed|conflict reason=...`，
  不含密钥材料或密文全文。

响应字段：`envelope`（结果密文）、`migrated`（该请求编号首次提交时是否发生了真实重包裹）、
`replayed`（本次响应是否为重放）。

## 4. 版本兼容与迁移规则

- **有序轮换**：轮换在密钥环写锁内完成，版本号严格单调递增；旧版本保持 `ACTIVE`，
  历史密文仍可解密。
- **停用**：`disable` 将版本置为 `DISABLED`，此后该版本的解密/重包裹请求一律以
  `KEY_DISABLED` 拒绝；默认拒绝停用最后一个活跃密钥（`keyring.allow-disable-last-active=false`）。
- **未知版本**：密文版本线索在密钥环中不存在时以 `UNKNOWN_KEY_VERSION` 拒绝。
- **重包裹迁移**：解开旧 KEK 包裹的 DEK，用当前活跃 KEK 重新包裹；数据密文段、
  dataIv、contextTag 原样保留，迁移前后明文与 DEK 语义不变。
- **并发一致性**：密钥环使用公平读写锁 + 原子落盘（临时文件 + atomic rename）。
  解密/重包裹持读锁，轮换/停用持写锁，因此并发下不会观察到半迁移状态或半写入的密钥环文件。
- **错误分类**（REST 错误码 / HTTP 状态）：

| 异常 | 错误码 | HTTP |
|---|---|---|
| `UnauthorizedOperationException` | `UNAUTHORIZED_OPERATION` | 403 |
| `MalformedCiphertextException` | `MALFORMED_CIPHERTEXT` | 400 |
| `UnknownKeyVersionException` | `UNKNOWN_KEY_VERSION` | 422 |
| `KeyDisabledException` | `KEY_DISABLED` | 422 |
| `ContextMismatchException` | `CONTEXT_MISMATCH` | 422 |
| `CiphertextIntegrityException` | `CIPHERTEXT_INTEGRITY` | 422 |
| `MigrationConflictException` | `MIGRATION_CONFLICT` | 409 |
| `KeyRingUnlockException` | `KEY_RING_UNLOCK` | 500 |
| 参数缺失/非法（如 requestId 为空） | `BAD_REQUEST` | 400 |

底层 `GeneralSecurityException` 一律映射为上述对外异常，不原样透出。

## 5. 配置项

| 配置 | 默认 | 语义 |
|---|---|---|
| `keyring.storage-path` | `./data/keyring.json` | 密钥环本地持久化文件路径 |
| `keyring.admin-token` | 环境变量 `KEYRING_ADMIN_TOKEN`，缺省 `local-dev-admin-token` | 管理操作令牌；置空时拒绝一切管理操作 |
| `keyring.allow-disable-last-active` | `false` | 是否允许停用最后一个活跃密钥 |
| `keyring.root-key` | 环境变量 `KEYRING_ROOT_KEY`，**缺省为空** | 根口令：派生根密钥包裹主密钥材料后落盘；为空时拒绝启动，绝不退化为明文 |
| `keyring.migration-records-path` | `./data/migration-records.json` | 迁移请求记录持久化文件路径 |
| `keyring.migration-max-records` | `10000` | 迁移请求记录上限；超出后按 FIFO 淘汰最旧记录 |

## 6. 本地验证方法

```bash
# 运行全部测试（幂等迁移、并发恰好一次、重启重放、冲突、记录淘汰、
# 落盘保护、旧格式升级、根口令缺失/错误，以及既有加解密/篡改/上下文/停用/未授权回归）
mvn test

# 启动服务（必须提供根口令，否则拒绝启动）
KEYRING_ROOT_KEY=local-dev-root-key mvn spring-boot:run

# 加密
curl -s -X POST localhost:8080/api/crypto/encrypt \
  -H 'Content-Type: application/json' \
  -d '{"context":"tenant=demo","plaintextBase64":"aGVsbG8="}'

# 解密（把上一步返回的 envelope 填入）
curl -s -X POST localhost:8080/api/crypto/decrypt \
  -H 'Content-Type: application/json' \
  -d '{"context":"tenant=demo","envelope":"<envelope>"}'

# 轮换（需管理令牌）
curl -s -X POST localhost:8080/api/admin/keys/rotate -H 'X-Admin-Token: local-dev-admin-token'

# 重包裹迁移（带请求编号；重复提交同一 requestId+输入 → replayed=true，密文一致）
curl -s -X POST localhost:8080/api/migration/rewrap \
  -H 'Content-Type: application/json' \
  -d '{"requestId":"req-0001","context":"tenant=demo","envelope":"<envelope>"}'

# 同一 requestId 换不同 envelope 再提交 → 409 MIGRATION_CONFLICT

# 停用旧版本
curl -s -X POST 'localhost:8080/api/admin/keys/disable?version=1' -H 'X-Admin-Token: local-dev-admin-token'

# 验证落盘保护：密钥环文件中只有包裹后的材料，搜不到明文材料字段
cat data/keyring.json   # 应看到 "formatVersion":2 与 wrappedMaterialBase64，无 materialBase64

# 验证旧格式升级：把旧格式（含明文 materialBase64、无 formatVersion）的 keyring.json
# 放到 keyring.storage-path，启动服务后文件会被立即改写为 v2，既有密文照常可解。
```

## 7. 代码结构

```
crypto/      KeyRing（v2 包裹落盘 + 旧格式升级 + 锁）、KeyRingProtection（根口令派生/包裹）、
             MasterKeyService（管理+鉴权）、EnvelopeCipher、RewrapService、CiphertextEnvelope
migration/   MigrationService（按请求幂等、恰好一次、冲突拒绝）、
             MigrationRecordStore（持久化、上限、FIFO 淘汰）、MigrationRecord
errors/      可区分异常体系（CryptoServiceException 及其子类，
             含 MigrationConflictException、KeyRingUnlockException）
api/         REST 入口（crypto / admin / migration）与统一异常映射
config/      KeyRingProperties、Bean 装配、启动时密钥环初始化
audit/       审计日志（不记录密钥材料）
tests/       单测覆盖：幂等迁移（重复/并发/重启/冲突/淘汰）、落盘保护与旧格式升级、
             根口令缺失/错误，以及并发、篡改、上下文、停用、未授权等既有回归
```
