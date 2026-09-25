package com.github.h3yow.envelopeencryptionkeyringjava.api;

import com.github.h3yow.envelopeencryptionkeyringjava.errors.CiphertextIntegrityException;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.ContextMismatchException;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.CryptoServiceException;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.KeyDisabledException;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.MalformedCiphertextException;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.UnauthorizedOperationException;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.UnknownKeyVersionException;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** 将可区分异常映射为稳定错误码，不泄露内部细节。 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Map<Class<? extends CryptoServiceException>, HttpStatus> STATUS = Map.of(
            UnauthorizedOperationException.class, HttpStatus.FORBIDDEN,
            UnknownKeyVersionException.class, HttpStatus.UNPROCESSABLE_ENTITY,
            KeyDisabledException.class, HttpStatus.UNPROCESSABLE_ENTITY,
            MalformedCiphertextException.class, HttpStatus.BAD_REQUEST,
            CiphertextIntegrityException.class, HttpStatus.UNPROCESSABLE_ENTITY,
            ContextMismatchException.class, HttpStatus.UNPROCESSABLE_ENTITY);

    public record ErrorBody(String code, String message) {
    }

    @ExceptionHandler(CryptoServiceException.class)
    public ResponseEntity<ErrorBody> handle(CryptoServiceException ex) {
        HttpStatus status = STATUS.getOrDefault(ex.getClass(), HttpStatus.INTERNAL_SERVER_ERROR);
        String code = ex.getClass().getSimpleName().replace("Exception", "")
                .replaceAll("(?<=[a-z])(?=[A-Z])", "_").toUpperCase();
        return ResponseEntity.status(status).body(new ErrorBody(code, ex.getMessage()));
    }
}
