package com.github.h3yow.envelopeencryptionkeyringjava.web;

import com.github.h3yow.envelopeencryptionkeyringjava.auth.AuthService;
import com.github.h3yow.envelopeencryptionkeyringjava.auth.Caller;
import com.github.h3yow.envelopeencryptionkeyringjava.service.KeyAdminService;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.KeyView;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.RotateResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 密钥管理入口：仅 ADMIN 令牌可用。
 */
@RestController
public class KeyAdminController {

    private final KeyAdminService keyAdminService;
    private final AuthService authService;

    public KeyAdminController(KeyAdminService keyAdminService, AuthService authService) {
        this.keyAdminService = keyAdminService;
        this.authService = authService;
    }

    @GetMapping("/api/v1/admin/keys")
    public List<KeyView> list(
            @RequestHeader(name = "Authorization", required = false) String authorization) {
        Caller caller = authService.authenticate(authorization);
        return keyAdminService.list(caller);
    }

    @PostMapping("/api/v1/admin/keys/rotate")
    public RotateResponse rotate(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestParam(name = "reason", required = false) String reason) {
        Caller caller = authService.authenticate(authorization);
        return keyAdminService.rotate(caller, reason);
    }

    @PostMapping("/api/v1/admin/keys/{version}/disable")
    public Map<String, Object> disable(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @PathVariable("version") String version) {
        Caller caller = authService.authenticate(authorization);
        boolean changed = keyAdminService.disable(caller, version);
        return Map.of("version", version, "status", "DISABLED", "changed", changed);
    }
}
