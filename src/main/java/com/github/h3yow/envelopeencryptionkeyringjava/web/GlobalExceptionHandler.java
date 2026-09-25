package com.github.h3yow.envelopeencryptionkeyringjava.web;

import com.github.h3yow.envelopeencryptionkeyringjava.auth.AccessDeniedException;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.CryptoException;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.ErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.Map;

/**
 * 统一异常映射。
 *
 * <p>对外响应只含 errorCode/message/timestamp，message 为固定安全文案，
 * 底层异常（cause）仅记录到服务端日志，绝不透传给调用方。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    public record ErrorBody(String errorCode, String message, String timestamp) {
    }

    @ExceptionHandler(CryptoException.class)
    public ResponseEntity<ErrorBody> handleCrypto(CryptoException ex) {
        // cause 只进日志；对外只暴露错误码与固定消息
        if (ex.getCause() != null) {
            log.warn("crypto failure mapped: code={} message={} causeType={}",
                    ex.getErrorCode(), ex.getMessage(), ex.getCause().getClass().getSimpleName());
        }
        return ResponseEntity.status(statusOf(ex.getErrorCode()))
                .body(new ErrorBody(ex.getErrorCode().name(), ex.getMessage(), Instant.now().toString()));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorBody> handleAccessDenied(AccessDeniedException ex) {
        log.warn("access denied: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new ErrorBody(ErrorCode.UNAUTHORIZED.name(), ex.getMessage(), Instant.now().toString()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorBody> handleUnreadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorBody(ErrorCode.INVALID_REQUEST.name(),
                        "malformed JSON request body", Instant.now().toString()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleUnexpected(Exception ex) {
        // 兜底：不回传异常类名/堆栈，避免泄露内部实现
        log.error("unexpected error", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of(
                        "errorCode", ErrorCode.INTERNAL_ERROR.name(),
                        "message", "internal error",
                        "timestamp", Instant.now().toString()));
    }

    private HttpStatus statusOf(ErrorCode code) {
        return switch (code) {
            case UNAUTHORIZED -> HttpStatus.FORBIDDEN;
            case KEY_VERSION_UNKNOWN, KEY_VERSION_DISABLED -> HttpStatus.CONFLICT;
            case CIPHERTEXT_MALFORMED, INVALID_REQUEST, IDEMPOTENCY_CONFLICT -> HttpStatus.BAD_REQUEST;
            case CONTEXT_MISMATCH, CIPHERTEXT_TAMPERED -> HttpStatus.UNPROCESSABLE_ENTITY;
            case NO_ACTIVE_KEY -> HttpStatus.SERVICE_UNAVAILABLE;
            case INTERNAL_ERROR -> HttpStatus.INTERNAL_SERVER_ERROR;
        };
    }
}
