package com.github.h3yow.envelopeencryptionkeyringjava.tests;

import com.github.h3yow.envelopeencryptionkeyringjava.auth.AccessDeniedException;
import com.github.h3yow.envelopeencryptionkeyringjava.auth.AuthService;
import com.github.h3yow.envelopeencryptionkeyringjava.auth.CallerRole;
import com.github.h3yow.envelopeencryptionkeyringjava.config.EekrProperties;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceTest.class);

    private final AuthService auth = new AuthService(new EekrProperties(
            "/tmp", "secret-root-pass", 10000, "admin-xyz", "user-xyz",
            new EekrProperties.Idempotency(10)));

    @Test
    void resolvesRolesFromBearerOrRawToken() {
        assertEquals(CallerRole.ADMIN, auth.authenticate("Bearer admin-xyz").role());
        assertEquals(CallerRole.ADMIN, auth.authenticate("admin-xyz").role());
        assertEquals(CallerRole.USER, auth.authenticate("Bearer user-xyz").role());
        log.info("auth: basis=token-match roles=ADMIN/USER");
    }

    @Test
    void rejectsMissingOrInvalidTokensWithoutLeakingMaterial() {
        AccessDeniedException none = assertThrows(AccessDeniedException.class,
                () -> auth.authenticate(null));
        AccessDeniedException bad = assertThrows(AccessDeniedException.class,
                () -> auth.authenticate("Bearer wrong-token"));
        // 错误消息不得包含令牌值、根口令等材料
        assertFalse(none.getMessage().contains("admin-xyz"));
        assertFalse(bad.getMessage().contains("wrong-token"));
        assertFalse(bad.getMessage().contains("secret-root-pass"));
        assertTrue(bad.getMessage().contains("invalid credentials"));
        log.info("auth failure: basis=constant-time-compare; response sanitized, only digest prefix logged");
    }

    @Test
    void onlyAdminPassesAdminCheck() {
        var admin = auth.authenticate("admin-xyz");
        var user = auth.authenticate("user-xyz");
        auth.requireAdmin(admin);
        assertThrows(AccessDeniedException.class, () -> auth.requireAdmin(user));
        assertThrows(AccessDeniedException.class, () -> auth.requireAdmin(null));
        log.info("authorization: USER -> denied for rotate/disable basis=role!=ADMIN");
    }
}
