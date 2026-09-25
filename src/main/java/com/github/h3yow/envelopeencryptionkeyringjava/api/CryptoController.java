package com.github.h3yow.envelopeencryptionkeyringjava.api;

import com.github.h3yow.envelopeencryptionkeyringjava.crypto.EnvelopeCipher;
import java.util.Base64;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 信封加解密 REST 入口。 */
@RestController
@RequestMapping("/api/crypto")
public class CryptoController {

    private final EnvelopeCipher cipher;

    public CryptoController(EnvelopeCipher cipher) {
        this.cipher = cipher;
    }

    public record EncryptRequest(String context, String plaintextBase64) {
    }

    public record EncryptResponse(String envelope) {
    }

    public record DecryptRequest(String context, String envelope) {
    }

    public record DecryptResponse(String plaintextBase64) {
    }

    @PostMapping("/encrypt")
    public EncryptResponse encrypt(@RequestBody EncryptRequest request) {
        byte[] plaintext = Base64.getDecoder().decode(request.plaintextBase64());
        return new EncryptResponse(cipher.encrypt(request.context(), plaintext));
    }

    @PostMapping("/decrypt")
    public DecryptResponse decrypt(@RequestBody DecryptRequest request) {
        byte[] plaintext = cipher.decrypt(request.context(), request.envelope());
        return new DecryptResponse(Base64.getEncoder().encodeToString(plaintext));
    }
}
