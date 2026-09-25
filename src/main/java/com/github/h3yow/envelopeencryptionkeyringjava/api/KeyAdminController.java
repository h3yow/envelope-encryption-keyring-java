package com.github.h3yow.envelopeencryptionkeyringjava.api;

import com.github.h3yow.envelopeencryptionkeyringjava.crypto.MasterKey;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.MasterKeyService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** 密钥管理 REST 入口：轮换与停用，需管理令牌。 */
@RestController
@RequestMapping("/api/admin/keys")
public class KeyAdminController {

    private final MasterKeyService masterKeyService;

    public KeyAdminController(MasterKeyService masterKeyService) {
        this.masterKeyService = masterKeyService;
    }

    public record RotateResponse(int newVersion) {
    }

    @PostMapping("/rotate")
    public RotateResponse rotate(@RequestHeader("X-Admin-Token") String token) {
        MasterKey key = masterKeyService.rotate(token);
        return new RotateResponse(key.getVersion());
    }

    @PostMapping("/disable")
    public void disable(@RequestHeader("X-Admin-Token") String token, @RequestParam int version) {
        masterKeyService.disable(token, version);
    }
}
