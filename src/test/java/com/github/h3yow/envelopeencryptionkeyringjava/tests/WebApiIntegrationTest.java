package com.github.h3yow.envelopeencryptionkeyringjava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Base64;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 端到端 HTTP 测试：权限边界、轮换、停用、重包裹幂等、各类可区分错误码。
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestPropertySource(properties = {
        "eekr.data-dir=${java.io.tmpdir}/eekr-web-it",
        "eekr.root-key-passphrase=web-it-pass",
        "eekr.kdf-iterations=10000",
        "eekr.admin-token=it-admin",
        "eekr.user-token=it-user"
})
class WebApiIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(WebApiIntegrationTest.class);
    private static final String ADMIN = "Bearer it-admin";
    private static final String USER = "Bearer it-user";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper mapper;

    private static String v1Cipher;

    @org.junit.jupiter.api.BeforeAll
    static void cleanDataDir() throws Exception {
        java.nio.file.Path dir = java.nio.file.Path.of(
                System.getProperty("java.io.tmpdir"), "eekr-web-it");
        if (java.nio.file.Files.exists(dir)) {
            try (var walk = java.nio.file.Files.walk(dir)) {
                walk.sorted(java.util.Comparator.reverseOrder())
                        .forEach(path -> {
                            try {
                                java.nio.file.Files.deleteIfExists(path);
                            } catch (java.io.IOException ignored) {
                            }
                        });
            }
        }
        log.info("web integration start: basis=full http stack with isolated data dir");
    }

    private String json(Map<String, ?> body) throws Exception {
        return mapper.writeValueAsString(body);
    }

    @Test
    @Order(1)
    void unauthenticatedAndUnauthorizedOperationsAreRejected() throws Exception {
        mockMvc.perform(post("/api/v1/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("plaintext", "x", "context", "c"))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("UNAUTHORIZED"));

        mockMvc.perform(post("/api/v1/admin/keys/rotate").header("Authorization", USER))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("UNAUTHORIZED"));
        mockMvc.perform(post("/api/v1/admin/keys/v1/disable").header("Authorization", USER))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("UNAUTHORIZED"));
        mockMvc.perform(get("/api/v1/admin/keys").header("Authorization", USER))
                .andExpect(status().isForbidden());

        mockMvc.perform(post("/api/v1/encrypt").header("Authorization", "Bearer nope")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("plaintext", "x", "context", "c"))))
                .andExpect(status().isForbidden())
                .andExpect(r -> {
                    String body = r.getResponse().getContentAsString();
                    if (body.contains("it-admin") || body.contains("it-user")) {
                        throw new AssertionError("鉴权失败响应泄露令牌材料: " + body);
                    }
                });
        log.info("web authz: unauthenticated/USER-management -> UNAUTHORIZED basis=role-check; no token leaked");
    }

    @Test
    @Order(2)
    void encryptDecryptAndDistinctErrors() throws Exception {
        MvcResult enc = mockMvc.perform(post("/api/v1/encrypt")
                        .header("Authorization", USER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("plaintext", "topsecret", "context", "tenant-A"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keyVersion").value("v1"))
                .andReturn();
        v1Cipher = mapper.readTree(enc.getResponse().getContentAsString()).get("ciphertext").asText();

        mockMvc.perform(post("/api/v1/decrypt")
                        .header("Authorization", USER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("context", "tenant-B", "ciphertext", v1Cipher))))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.errorCode").value("CONTEXT_MISMATCH"));

        byte[] raw = Base64.getDecoder().decode(v1Cipher);
        raw[raw.length / 2] ^= 0x02;
        String tampered = Base64.getEncoder().encodeToString(raw);
        mockMvc.perform(post("/api/v1/decrypt")
                        .header("Authorization", USER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("context", "tenant-A", "ciphertext", tampered))))
                .andExpect(r -> {
                    int status = r.getResponse().getStatus();
                    String code = mapper.readTree(r.getResponse().getContentAsString())
                            .get("errorCode").asText();
                    if (status != 400 && status != 422) {
                        throw new AssertionError("unexpected status " + status);
                    }
                    if (!"CIPHERTEXT_MALFORMED".equals(code) && !"CIPHERTEXT_TAMPERED".equals(code)) {
                        throw new AssertionError("unexpected code " + code);
                    }
                });

        mockMvc.perform(post("/api/v1/decrypt")
                        .header("Authorization", USER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("context", "c", "ciphertext", "%%%notb64%%%"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("CIPHERTEXT_MALFORMED"));

        mockMvc.perform(post("/api/v1/decrypt")
                        .header("Authorization", USER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("context", "tenant-A", "ciphertext", v1Cipher))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.plaintext").value("topsecret"));
        log.info("web crypto: keyVersion=v1 basis=full-flow; mismatch/tamper/malformed distinguishable");
    }

    @Test
    @Order(3)
    void rotateDisableAndVersionRejection() throws Exception {
        mockMvc.perform(post("/api/v1/admin/keys/rotate?reason=policy")
                        .header("Authorization", ADMIN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.newVersion").value("v2"))
                .andExpect(jsonPath("$.previousVersion").value("v1"));

        mockMvc.perform(post("/api/v1/decrypt")
                        .header("Authorization", USER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("context", "tenant-A", "ciphertext", v1Cipher))))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/v1/admin/keys/v1/disable").header("Authorization", ADMIN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.changed").value(true));

        mockMvc.perform(post("/api/v1/decrypt")
                        .header("Authorization", USER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("context", "tenant-A", "ciphertext", v1Cipher))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.errorCode").value("KEY_VERSION_DISABLED"));

        mockMvc.perform(post("/api/v1/admin/keys/v404/disable").header("Authorization", ADMIN))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.errorCode").value("KEY_VERSION_UNKNOWN"));

        MvcResult list = mockMvc.perform(get("/api/v1/admin/keys").header("Authorization", ADMIN))
                .andExpect(status().isOk())
                .andReturn();
        String body = list.getResponse().getContentAsString();
        org.junit.jupiter.api.Assertions.assertFalse(body.contains("wrappedKey"),
                "版本视图不得包含密钥材料");
        log.info("web lifecycle: rotate v1->v2, disable v1 => DECRYPT rejected basis=KEY_VERSION_DISABLED");
    }

    @Test
    @Order(4)
    void rewrapRecoversDisabledDataAndIsIdempotent() throws Exception {
        MvcResult r1 = mockMvc.perform(post("/api/v1/rewrap")
                        .header("Authorization", USER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("ciphertext", v1Cipher, "context", "tenant-A",
                                "requestId", "it-rid-1"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keyVersion").value("v2"))
                .andExpect(jsonPath("$.replayed").value(false))
                .andReturn();
        String migrated = mapper.readTree(r1.getResponse().getContentAsString())
                .get("ciphertext").asText();

        mockMvc.perform(post("/api/v1/rewrap")
                        .header("Authorization", USER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("ciphertext", v1Cipher, "context", "tenant-A",
                                "requestId", "it-rid-1"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.replayed").value(true))
                .andExpect(jsonPath("$.ciphertext").value(migrated));

        mockMvc.perform(post("/api/v1/decrypt")
                        .header("Authorization", USER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("context", "tenant-A", "ciphertext", migrated))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.plaintext").value("topsecret"));
        log.info("web rewrap: v1(disabled)->v2 plaintext restored; replay idempotent basis=stored-record");
    }
}
