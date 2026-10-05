package com.github.h3yow.envelopeencryptionkeyringjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** REST 多入口一致性：加解密、轮换、重包裹、鉴权失败与错误码可区分。 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApiIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(ApiIntegrationTest.class);
    private static final String ADMIN = "it-admin-token";
    private static final String CTX = "tenant=rest";

    @TempDir
    static Path sharedDir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("keyring.storage-path", () -> sharedDir.resolve("keyring.json").toString());
        registry.add("keyring.admin-token", () -> ADMIN);
        registry.add("keyring.root-password", () -> "it-root-password");
        registry.add("keyring.migration-store-path",
                () -> sharedDir.resolve("migration-requests.json").toString());
    }

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    void restEntriesAreConsistentAndErrorsDistinguishable() {
        // 1. REST 加密
        String plaintextB64 = Base64.getEncoder().encodeToString(
                "via-rest".getBytes(StandardCharsets.UTF_8));
        ResponseEntity<Map> enc = rest.postForEntity(url("/api/crypto/encrypt"),
                Map.of("context", CTX, "plaintextBase64", plaintextB64), Map.class);
        assertEquals(HttpStatus.OK, enc.getStatusCode());
        String envelope = (String) enc.getBody().get("envelope");
        assertNotNull(envelope);
        log.info("rest encrypt ok envelopePrefix={}", envelope.substring(0, envelope.indexOf('.')));

        // 2. REST 解密往返
        ResponseEntity<Map> dec = rest.postForEntity(url("/api/crypto/decrypt"),
                Map.of("context", CTX, "envelope", envelope), Map.class);
        assertEquals(HttpStatus.OK, dec.getStatusCode());
        assertEquals(plaintextB64, dec.getBody().get("plaintextBase64"));

        // 3. 上下文不匹配 → 可区分错误码
        ResponseEntity<Map> wrongCtx = rest.postForEntity(url("/api/crypto/decrypt"),
                Map.of("context", "tenant=other", "envelope", envelope), Map.class);
        log.info("rest wrongCtx status={} code={}", wrongCtx.getStatusCode(), wrongCtx.getBody().get("code"));
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, wrongCtx.getStatusCode());
        assertEquals("CONTEXT_MISMATCH", wrongCtx.getBody().get("code"));

        // 4. 未授权管理操作 → 403，且不泄露密钥材料
        ResponseEntity<Map> noAuth = rest.postForEntity(url("/api/admin/keys/rotate"),
                new HttpEntity<>(new HttpHeaders()), Map.class);
        // 缺少 header 会由 Spring 报 400；用错误令牌验证 403
        HttpHeaders bad = new HttpHeaders();
        bad.set("X-Admin-Token", "wrong");
        ResponseEntity<Map> forbidden = rest.exchange(url("/api/admin/keys/rotate"),
                HttpMethod.POST, new HttpEntity<>(bad), Map.class);
        log.info("rest badToken status={} code={}", forbidden.getStatusCode(), forbidden.getBody().get("code"));
        assertEquals(HttpStatus.FORBIDDEN, forbidden.getStatusCode());
        assertEquals("UNAUTHORIZED_OPERATION", forbidden.getBody().get("code"));
        assertTrue(!forbidden.getBody().toString().contains(ADMIN), "不得泄露令牌或密钥材料");

        // 5. 授权轮换 → 按 requestId 重包裹 → 同号重放，密文一致
        HttpHeaders good = new HttpHeaders();
        good.set("X-Admin-Token", ADMIN);
        ResponseEntity<Map> rotated = rest.exchange(url("/api/admin/keys/rotate"),
                HttpMethod.POST, new HttpEntity<>(good), Map.class);
        assertEquals(HttpStatus.OK, rotated.getStatusCode());
        int newVersion = (Integer) rotated.getBody().get("newVersion");
        log.info("rest rotated newVersion={}", newVersion);

        ResponseEntity<Map> rw1 = rest.postForEntity(url("/api/migration/rewrap"),
                Map.of("requestId", "req-001", "context", CTX, "envelope", envelope), Map.class);
        assertEquals(HttpStatus.OK, rw1.getStatusCode());
        assertEquals(Boolean.TRUE, rw1.getBody().get("migrated"));
        assertEquals(Boolean.FALSE, rw1.getBody().get("replay"), "首次提交必须是真实迁移");
        String migrated = (String) rw1.getBody().get("envelope");

        ResponseEntity<Map> rw2 = rest.postForEntity(url("/api/migration/rewrap"),
                Map.of("requestId", "req-001", "context", CTX, "envelope", envelope), Map.class);
        log.info("rest rewrap migrated1={} replay2={}",
                rw1.getBody().get("migrated"), rw2.getBody().get("replay"));
        assertEquals(Boolean.TRUE, rw2.getBody().get("replay"), "同编号重复提交必须是重放");
        assertEquals(Boolean.TRUE, rw2.getBody().get("migrated"), "重放返回首次的迁移结论");
        assertEquals(migrated, rw2.getBody().get("envelope"), "重放必须返回与首次一致的密文");

        // 同编号不同内容 → 409 IDEMPOTENCY_CONFLICT，与损坏/版本错误区分
        ResponseEntity<Map> conflict = rest.postForEntity(url("/api/migration/rewrap"),
                Map.of("requestId", "req-001", "context", "tenant=other", "envelope", envelope),
                Map.class);
        log.info("rest conflict status={} code={}", conflict.getStatusCode(),
                conflict.getBody().get("code"));
        assertEquals(HttpStatus.CONFLICT, conflict.getStatusCode());
        assertEquals("IDEMPOTENCY_CONFLICT", conflict.getBody().get("code"));

        // 6. 迁移后的密文经 REST 解密仍得到原明文
        ResponseEntity<Map> dec2 = rest.postForEntity(url("/api/crypto/decrypt"),
                Map.of("context", CTX, "envelope", migrated), Map.class);
        assertEquals(HttpStatus.OK, dec2.getStatusCode());
        assertEquals(plaintextB64, dec2.getBody().get("plaintextBase64"));

        // 7. 结构不完整密文 → 400 MALFORMED_CIPHERTEXT
        ResponseEntity<Map> malformed = rest.postForEntity(url("/api/crypto/decrypt"),
                Map.of("context", CTX, "envelope", "EK1.1.aa"), Map.class);
        assertEquals(HttpStatus.BAD_REQUEST, malformed.getStatusCode());
        assertEquals("MALFORMED_CIPHERTEXT", malformed.getBody().get("code"));
    }
}
