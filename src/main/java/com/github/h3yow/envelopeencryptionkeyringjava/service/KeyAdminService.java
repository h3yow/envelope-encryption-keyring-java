package com.github.h3yow.envelopeencryptionkeyringjava.service;

import com.github.h3yow.envelopeencryptionkeyringjava.auth.AuthService;
import com.github.h3yow.envelopeencryptionkeyringjava.auth.Caller;
import com.github.h3yow.envelopeencryptionkeyringjava.keyring.KeyRing;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.KeyView;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.RotateResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 主密钥管理：列表、生成、启停、有序轮换。
 * 所有方法都强制 ADMIN；普通 USER 调用在触碰任何密钥状态前即被拒绝。
 */
@Service
public class KeyAdminService {

    private static final Logger log = LoggerFactory.getLogger(KeyAdminService.class);

    private final KeyRing keyRing;
    private final AuthService authService;

    public KeyAdminService(KeyRing keyRing, AuthService authService) {
        this.keyRing = keyRing;
        this.authService = authService;
    }

    public List<KeyView> list(Caller caller) {
        authService.requireAdmin(caller);
        return keyRing.listVersions().stream()
                .map(v -> new KeyView(v.version(), v.status(), v.current(), v.createdAt()))
                .toList();
    }

    public RotateResponse rotate(Caller caller, String reason) {
        authService.requireAdmin(caller);
        String previous = keyRing.listVersions().stream()
                .filter(KeyRing.KeyViewSnapshot::current)
                .map(KeyRing.KeyViewSnapshot::version)
                .findFirst().orElse(null);
        String next = keyRing.rotate(reason == null ? "manual" : reason);
        log.info("admin rotate: caller={} previous={} next={} basis=admin-authorized",
                caller.name(), previous, next);
        return new RotateResponse(next, previous);
    }

    /** @return true 表示本次停用生效；false 表示此前已是停用态 */
    public boolean disable(Caller caller, String version) {
        authService.requireAdmin(caller);
        boolean changed = keyRing.disable(version);
        log.info("admin disable: caller={} version={} changed={} basis=admin-authorized",
                caller.name(), version, changed);
        return changed;
    }
}
