# Envelope Encryption Keyring (Java / Spring Boot)

本地可运行的密钥分层加密与轮换服务：以本地持久化文件模拟密钥环，提供信封加解密、
主密钥有序轮换、历史密文重包裹迁移，并在多入口（REST / 服务层）与并发条件下保证结论一致、可审计。
本版新增：**迁移按请求编号（requestId）幂等**，以及**密钥环根口令落盘保护与旧格式平滑升级**。

## 1. 密钥分层与权限边界

```
KEK（主密钥，密钥环内按版本管理，本地 keyring.json 根口令包裹后持久化）
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
  只记录版本号、请求编号、内容指纹前缀与判定依据，**绝不记录密钥材料、根口令或密文全文**。

## 2. 按请求编号幂等的迁移

迁移入口：`POST /api/migration/rewrap`，请求体必须带调用方自己生成的 `requestId`：

```json
{ "requestId": "任意调用方生成的唯一编号", "context": "tenant=demo", "envelope": "<待迁移密文>" }
```

- **编号语义**：`requestId` 由调用方生成（建议 UUID），标识“这一次迁移意图”。服务端把
  编号与该次请求内容（`context` + `envelope` 的规范化 SHA-256 指纹）绑定并落盘。
- **真实迁移只发生一次**：同一编号 + 同一内容，无论是并发同时打到服务上，还是服务重启后
  再提交，都只有第一次执行真实重包裹；之后每次都直接返回**与第一次逐字节一致的密文**，
  响应中 `replay=true`、`migrated` 反映首次结论（首次真实发生了版本迁移则为 `true`）。
  并发实现为“每编号一把锁 + 落盘双检”，一批同号请求里真实迁移恰好一次，其余全部重放。
- **重放判定**：命中已存记录且内容指纹一致 → `decision=replay`，并刷新该记录的最近使用时间
  （影响淘汰顺序）。响应示例：
  ```json
  { "requestId": "req-1", "envelope": "EK1....", "migrated": true, "replay": true }
  ```
- **冲突判定（与其它失败明确区分）**：同一编号但内容不同（换了 `context` 或 `envelope`），
  返回 `409 IDEMPOTENCY_CONFLICT`，且不覆盖原记录；调用方应**更换新编号**后重试。
  该错误与下列失败互不为一类：密文结构损坏 `400 MALFORMED_CIPHERTEXT`、引用未知版本
  `422 UNKNOWN_KEY_VERSION`、密钥停用 `422 KEY_DISABLED`、篡改
  `422 CIPHERTEXT_INTEGRITY`、上下文不匹配 `422 CONTEXT_MISMATCH`。
- **失败不占编号**：真实迁移本身失败（版本/篡改/上下文等）时不写幂等记录，
  调用方修正输入后可沿用原编号重试。
- **记录上限与确定性淘汰**：迁移记录持久化在 `migration-requests.json`，条数受
  `keyring.migration-max-records` 限制。超限后按**最久未被重放优先**（访问序 LRU，
  同刻按插入序号）从头部淘汰；最近重放的记录最后被淘汰。被淘汰的编号再次提交时按
  新请求重新处理（可能再发生一次真实迁移），不会报错。
- 日志为每次判定给出依据：`decision=processed|replay|conflict`，以及
  `action=migration-evict ... reason=capacity reasonDetail=lru`；只含编号与指纹前缀。

## 3. 密钥环落盘保护与旧格式升级

- **受保护格式（wrapped-v1）**：配置根口令后，密钥环文件不再保存任何明文主密钥材料。
  落盘内容为 `format / kdf / kdfIterations / salt / iv / ciphertext`：整个密钥环 JSON 载荷
  用根口令经 **PBKDF2-HMAC-SHA256（310000 轮，每次随机 salt）** 派生 256 位包裹密钥，
  再以 **AES-256-GCM** 认证加密（AAD 绑定格式标识）。只拿到文件无法读出任何密钥材料。
- **根口令策略**：
  - `keyring.require-root-password=true`（默认）时，未配置 `keyring.root-password`
    直接**拒绝启动**，绝不退化成明文落盘。
  - 受保护文件用**错误口令**打开时，GCM 认证失败，返回 `503 KEY_RING_LOCKED`
    （“口令错误 / 文件被篡改”对外同为该错误，不提供更多可利用信息），且不破坏原文件。
  - 受保护文件在**没有口令**的情况下打开同样被拒绝，不会按明文降级解析。
  - 口令与派生密钥用后即清零；异常消息与日志中不出现口令或密钥材料。
- **旧格式平滑升级**：历史明文密钥环文件（直接含 `keys[].materialBase64`）在配置了根口令时
  可正常加载，并在加载事务内**一次性原子重写**为 wrapped-v1（审计 `action=keyring-upgrade`）：
  - 所有历史版本密钥原样保留，升级前发出的密文**照样可解**；
  - 版本号延续，升级后的轮换严格单调递增，重包裹迁移结论与升级前一致；
  - 升级后临时文件与正式文件都不含明文材料。
- **并发一致性**：密钥环使用公平读写锁 + 原子落盘（临时文件 + atomic rename）。
  解密/重包裹持读锁，轮换/停用持写锁，因此并发下不会观察到半迁移状态或半写入的密钥环文件。

## 4. 错误分类（REST 错误码 / HTTP 状态）

| 异常 | 错误码 | HTTP |
|---|---|---|
| `UnauthorizedOperationException` | `UNAUTHORIZED_OPERATION` | 403 |
| `MalformedCiphertextException` | `MALFORMED_CIPHERTEXT` | 400 |
| `UnknownKeyVersionException` | `UNKNOWN_KEY_VERSION` | 422 |
| `KeyDisabledException` | `KEY_DISABLED` | 422 |
| `ContextMismatchException` | `CONTEXT_MISMATCH` | 422 |
| `CiphertextIntegrityException` | `CIPHERTEXT_INTEGRITY` | 422 |
| `IdempotencyConflictException` | `IDEMPOTENCY_CONFLICT` | 409 |
| `KeyRingLockedException` | `KEY_RING_LOCKED` | 503 |

底层 `GeneralSecurityException` 一律映射为上述对外异常，不原样透出。

## 5. 配置项

| 配置 | 默认 | 语义 |
|---|---|---|
| `keyring.storage-path` | `./data/keyring.json` | 密钥环本地持久化文件路径 |
| `keyring.admin-token` | 环境变量 `KEYRING_ADMIN_TOKEN`，缺省 `local-dev-admin-token` | 管理操作令牌；置空时拒绝一切管理操作 |
| `keyring.allow-disable-last-active` | `false` | 是否允许停用最后一个活跃密钥 |
| `keyring.root-password` | 环境变量 `KEYRING_ROOT_PASSWORD`，**无默认值** | 密钥环落盘保护根口令；`require-root-password=true` 且未配置时拒绝启动 |
| `keyring.require-root-password` | `true` | 是否强制根口令（不允许退化成明文落盘） |
| `keyring.migration-store-path` | 空 | 迁移幂等记录文件；留空则取密钥环同目录 `migration-requests.json` |
| `keyring.migration-max-records` | `1000` | 迁移幂等记录上限，超限按最久未重放确定性淘汰 |

## 6. 本地验证方法

```bash
# 运行全部测试（含按编号幂等/并发恰好一次/重启重放/冲突/上限淘汰、
# 落盘保护/旧格式升级/口令缺失错误被拒，以及加解密、篡改、上下文、停用、未授权不回归）
mvn test

# 以根口令保护模式启动服务（根口令经环境变量注入）
KEYRING_ROOT_PASSWORD='local-dev-root-password' mvn spring-boot:run

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

# 按请求编号迁移（首次：replay=false）
curl -s -X POST localhost:8080/api/migration/rewrap \
  -H 'Content-Type: application/json' \
  -d '{"requestId":"demo-req-001","context":"tenant=demo","envelope":"<旧密文>"}'

# 同编号同内容再提交（重放：replay=true，envelope 与首次逐字节一致）
curl -s -X POST localhost:8080/api/migration/rewrap \
  -H 'Content-Type: application/json' \
  -d '{"requestId":"demo-req-001","context":"tenant=demo","envelope":"<旧密文>"}'

# 同编号换内容（冲突）：返回 409 IDEMPOTENCY_CONFLICT
curl -s -i -X POST localhost:8080/api/migration/rewrap \
  -H 'Content-Type: application/json' \
  -d '{"requestId":"demo-req-001","context":"tenant=other","envelope":"<旧密文>"}'

# 停用旧版本
curl -s -X POST 'localhost:8080/api/admin/keys/disable?version=1' -H 'X-Admin-Token: local-dev-admin-token'
```

落盘保护可直接目检：启动后 `data/keyring.json` 中只有 `format/kdf/kdfIterations/salt/iv/ciphertext`，
`grep materialBase64 data/keyring.json` 无任何命中；删掉环境变量 `KEYRING_ROOT_PASSWORD`
再启动会被拒绝；把一个旧明文密钥环放到该路径并带根口令启动，可观察到
`AUDIT action=keyring-upgrade ... to=wrapped-v1`，且旧密文仍可解密。

## 7. 代码结构

```
crypto/    KeyRing（持久化+锁+格式升级）、KeyMaterialProtector（根口令包裹）、
           MasterKeyService、EnvelopeCipher、RewrapService、CiphertextEnvelope、
           IdempotentMigrationService（按编号幂等）、MigrationRequestStore（LRU 落盘）
errors/    可区分异常体系（含 IDEMPOTENCY_CONFLICT、KEY_RING_LOCKED）
api/       REST 入口（crypto / admin / migration）与统一异常映射
config/    KeyRingProperties、Bean 装配、启动校验与密钥环初始化
audit/     审计日志（不记录密钥材料、口令或密文全文）
tests/     幂等/并发/重启/冲突/淘汰、落盘保护/升级/口令拒绝，以及加解密、篡改、上下文、停用、未授权
```
