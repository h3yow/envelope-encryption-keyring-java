package com.github.h3yow.envelopeencryptionkeyringjava.api;

import com.github.h3yow.envelopeencryptionkeyringjava.migration.MigrationService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 重包裹迁移 REST 入口：按请求编号幂等。
 *
 * <p>requestId 为调用方生成的请求编号：同号同输入重放首次结果（replayed=true），
 * 同号不同输入返回 409 MIGRATION_CONFLICT。
 */
@RestController
@RequestMapping("/api/migration")
public class MigrationController {

    private final MigrationService migrationService;

    public MigrationController(MigrationService migrationService) {
        this.migrationService = migrationService;
    }

    public record RewrapRequest(String requestId, String context, String envelope) {
    }

    public record RewrapResponse(String envelope, boolean migrated, boolean replayed) {
    }

    @PostMapping("/rewrap")
    public RewrapResponse rewrap(@RequestBody RewrapRequest request) {
        MigrationService.MigrationOutcome outcome =
                migrationService.migrate(request.requestId(), request.context(), request.envelope());
        return new RewrapResponse(outcome.envelope(), outcome.migrated(), outcome.replayed());
    }
}
