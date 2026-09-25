# Envelope Encryption Keyring (Java / Spring Boot)

本地可运行的密钥分层加密与轮换服务：以本地持久化文件模拟密钥环，提供信封加解密、
主密钥有序轮换、历史密文重包裹迁移，并在多入口（REST / 服务层）与并发条件下保证结论一致、可审计。

## 1. 密钥分层与权限边界

```
KEK（主密钥，密钥环内按版本管理，本地 keyring.json 持久化）
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
  只记录版本号与判定依据，绝不记录密钥材料或明文。

## 2. 版本兼容与迁移规则

- **有序轮换**：轮换在密钥环写锁内完成，版本号严格单调递增；旧版本保持 `ACTIVE`，
  历史密文仍可解密。
- **停用**：`disable` 将版本置为 `DISABLED`，此后该版本的解密/重包裹请求一律以
  `KEY_DISABLED` 拒绝；默认拒绝停用最后一个活跃密钥（`keyring.allow-disable-last-active=false`）。
- **未知版本**：密文版本线索在密钥环中不存在时以 `UNKNOWN_KEY_VERSION` 拒绝。
- **重包裹迁移**：解开旧 KEK 包裹的 DEK，用当前活跃 KEK 重新包裹；数据密文段、
  dataIv、contextTag 原样保留，迁移前后明文与 DEK 语义不变。
  已是当前版本的密文原样返回（`migrated=false`），**重复提交同一迁移请求天然幂等**。
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

底层 `GeneralSecurityException` 一律映射为上述对外异常，不原样透出。

## 3. 配置项

| 配置 | 默认 | 语义 |
|---|---|---|
| `keyring.storage-path` | `./data/keyring.json` | 密钥环本地持久化文件路径 |
| `keyring.admin-token` | 环境变量 `KEYRING_ADMIN_TOKEN`，缺省 `local-dev-admin-token` | 管理操作令牌；置空时拒绝一切管理操作 |
| `keyring.allow-disable-last-active` | `false` | 是否允许停用最后一个活跃密钥 |

## 4. 本地验证方法

```bash
# 运行全部测试（含并发轮换/重包裹、篡改、上下文不匹配、停用、未授权场景）
mvn test

# 启动服务
mvn spring-boot:run

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

# 重包裹迁移（幂等，可重复提交）
curl -s -X POST localhost:8080/api/migration/rewrap \
  -H 'Content-Type: application/json' \
  -d '{"context":"tenant=demo","envelope":"<envelope>"}'

# 停用旧版本
curl -s -X POST 'localhost:8080/api/admin/keys/disable?version=1' -H 'X-Admin-Token: local-dev-admin-token'
```

## 5. 代码结构

```
crypto/    KeyRing（持久化+锁）、MasterKeyService（管理+鉴权）、EnvelopeCipher、RewrapService、CiphertextEnvelope
errors/    可区分异常体系（CryptoServiceException 及其子类）
api/       REST 入口（crypto / admin / migration）与统一异常映射
config/    KeyRingProperties、Bean 装配、启动时密钥环初始化
audit/     审计日志（不记录密钥材料）
tests/     单测覆盖并发、篡改、上下文、停用、未授权、幂等与持久化恢复
```
