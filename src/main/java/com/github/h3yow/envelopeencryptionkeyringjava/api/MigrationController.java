package com.github.h3yow.envelopeencryptionkeyringjava.api;

import com.github.h3yow.envelopeencryptionkeyringjava.crypto.IdempotentMigrationService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 重包裹迁移 REST 入口（按请求编号幂等）。
 *
 * <p>调用方每次迁移必须带自己生成的 {@code requestId}：同编号同内容重复提交
 * （含并发与重启后）只会真实迁移一次，之后返回 {@code replay=true} 且密文与首次一致；
 * 同编号不同内容返回 {@code 409 IDEMPOTENCY_CONFLICT}。
 */
@RestController
@RequestMapping("/api/migration")
public class MigrationController {

    private final IdempotentMigrationService migrationService;

    public MigrationController(IdempotentMigrationService migrationService) {
        this.migrationService = migrationService;
    }

    public record RewrapRequest(String requestId, String context, String envelope) {
    }

    public record RewrapResponse(String requestId, String envelope, boolean migrated, boolean replay) {
    }

    @PostMapping("/rewrap")
    public RewrapResponse rewrap(@RequestBody RewrapRequest request) {
        IdempotentMigrationService.MigrationOutcome outcome =
                migrationService.submit(request.requestId(), request.context(), request.envelope());
        return new RewrapResponse(outcome.requestId(), outcome.envelope(),
                outcome.migrated(), outcome.replay());
    }
}
