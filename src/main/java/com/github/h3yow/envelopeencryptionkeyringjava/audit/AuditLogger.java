package com.github.h3yow.envelopeencryptionkeyringjava.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/** 审计日志：记录关键操作、密钥版本与判定依据，绝不记录密钥材料。 */
@Component
public class AuditLogger {
    private static final Logger log = LoggerFactory.getLogger("AUDIT");

    public void record(String action, String detail) {
        log.info("action={} {}", action, detail);
    }
}
