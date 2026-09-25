package com.github.h3yow.envelopeencryptionkeyringjava.auth;

import com.github.h3yow.envelopeencryptionkeyringjava.config.EekrProperties;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.ErrorCode;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * 令牌鉴权（本地模拟）。
 *
 * <p>管理令牌 -> ADMIN，可执行轮换/停用；普通令牌 -> USER，只能加解密与重包裹。
 * 鉴权失败统一抛 {@link AccessDeniedException}，消息不含令牌内容，仅含其摘要用于审计。
 */
@Component
public class AuthService {

    private final EekrProperties props;

    public AuthService(EekrProperties props) {
        this.props = props;
    }

    /** 解析 Authorization 头（"Bearer xxx" 或裸令牌均可）。 */
    public Caller authenticate(String authorizationHeader) {
        String token = extractToken(authorizationHeader);
        if (token == null || token.isBlank()) {
            throw new AccessDeniedException("missing credentials");
        }
        if (constantTimeEquals(token, props.adminToken())) {
            return new Caller(CallerRole.ADMIN, "admin");
        }
        if (constantTimeEquals(token, props.userToken())) {
            return new Caller(CallerRole.USER, "user");
        }
        throw new AccessDeniedException("invalid credentials token-sha256=" + sha256Prefix(token));
    }

    /** 要求管理权限，否则拒绝。 */
    public void requireAdmin(Caller caller) {
        if (caller == null || caller.role() != CallerRole.ADMIN) {
            throw new AccessDeniedException("admin privilege required for key management operations");
        }
    }

    private String extractToken(String header) {
        if (header == null) {
            return null;
        }
        String trimmed = header.trim();
        if (trimmed.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return trimmed.substring(7).trim();
        }
        return trimmed;
    }

    private boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private String sha256Prefix(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, 6);
        } catch (NoSuchAlgorithmException e) {
            return "unknown";
        }
    }

    /** 将鉴权异常映射为对外错误码（供异常处理器使用）。 */
    public static ErrorCode errorCode() {
        return ErrorCode.UNAUTHORIZED;
    }
}
