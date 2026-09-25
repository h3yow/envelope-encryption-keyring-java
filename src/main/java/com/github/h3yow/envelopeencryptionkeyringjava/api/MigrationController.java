package com.github.h3yow.envelopeencryptionkeyringjava.api;

import com.github.h3yow.envelopeencryptionkeyringjava.crypto.RewrapService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 重包裹迁移 REST 入口。 */
@RestController
@RequestMapping("/api/migration")
public class MigrationController {

    private final RewrapService rewrapService;

    public MigrationController(RewrapService rewrapService) {
        this.rewrapService = rewrapService;
    }

    public record RewrapRequest(String context, String envelope) {
    }

    public record RewrapResponse(String envelope, boolean migrated) {
    }

    @PostMapping("/rewrap")
    public RewrapResponse rewrap(@RequestBody RewrapRequest request) {
        RewrapService.RewrapResult result =
                rewrapService.rewrapWithResult(request.context(), request.envelope());
        return new RewrapResponse(result.envelope(), result.migrated());
    }
}
