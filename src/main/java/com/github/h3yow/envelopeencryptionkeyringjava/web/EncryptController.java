package com.github.h3yow.envelopeencryptionkeyringjava.web;

import com.github.h3yow.envelopeencryptionkeyringjava.auth.AuthService;
import com.github.h3yow.envelopeencryptionkeyringjava.auth.Caller;
import com.github.h3yow.envelopeencryptionkeyringjava.service.EncryptionService;
import com.github.h3yow.envelopeencryptionkeyringjava.service.RewrapService;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.DecryptRequest;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.DecryptResponse;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.EncryptRequest;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.EncryptResponse;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.RewrapRequest;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.RewrapResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * 业务入口：加密 / 解密 / 重包裹。
 * 加解密与重包裹对 USER、ADMIN 均开放；管理类操作在 {@link KeyAdminController}。
 */
@RestController
public class EncryptController {

    private final EncryptionService encryptionService;
    private final RewrapService rewrapService;
    private final AuthService authService;

    public EncryptController(EncryptionService encryptionService,
                             RewrapService rewrapService,
                             AuthService authService) {
        this.encryptionService = encryptionService;
        this.rewrapService = rewrapService;
        this.authService = authService;
    }

    @PostMapping("/api/v1/encrypt")
    public EncryptResponse encrypt(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestBody EncryptRequest request) {
        Caller caller = authService.authenticate(authorization);
        return encryptionService.encrypt(request);
    }

    @PostMapping("/api/v1/decrypt")
    public DecryptResponse decrypt(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestBody DecryptRequest request) {
        Caller caller = authService.authenticate(authorization);
        return encryptionService.decrypt(request);
    }

    @PostMapping("/api/v1/rewrap")
    public RewrapResponse rewrap(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestBody RewrapRequest request) {
        Caller caller = authService.authenticate(authorization);
        return rewrapService.rewrap(request);
    }
}
