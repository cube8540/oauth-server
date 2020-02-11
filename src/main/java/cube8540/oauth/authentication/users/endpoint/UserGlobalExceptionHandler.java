package cube8540.oauth.authentication.users.endpoint;

import cube8540.oauth.authentication.message.ErrorResponseMessage;
import cube8540.oauth.authentication.message.ResponseMessage;
import cube8540.oauth.authentication.users.domain.UserAlreadyExistsException;
import cube8540.oauth.authentication.users.domain.UserInvalidException;
import cube8540.oauth.authentication.users.domain.UserNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class UserGlobalExceptionHandler {


    @ExceptionHandler(UserInvalidException.class)
    public ResponseEntity<ResponseMessage> exceptionHandle(UserInvalidException e) {
        if (log.isInfoEnabled()) {
            log.info("User invalid data handle {}, {}", e.getClass(), e.getMessage());
        }
        ResponseMessage message = ErrorResponseMessage.badRequest(e.getErrors());
        return new ResponseEntity<>(message, message.getStatus());
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ResponseMessage> exceptionHandle(UserAlreadyExistsException e) {
        if (log.isErrorEnabled()) {
            log.error("User already exists handle {}, {}", e.getClass(), e.getMessage());
        }
        ResponseMessage message = ErrorResponseMessage.conflict(e.getMessage());
        return new ResponseEntity<>(message, message.getStatus());
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ResponseMessage> exceptionHandle(UserNotFoundException e) {
        if (log.isWarnEnabled()) {
            log.warn("User not found handle {}, {}", e.getClass(), e.getMessage());
        }
        ResponseMessage message = ErrorResponseMessage.notfound(e.getMessage());
        return new ResponseEntity<>(message, message.getStatus());
    }

}
