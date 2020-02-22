package cube8540.oauth.authentication.users.error;

import cube8540.oauth.authentication.error.ErrorMessage;
import cube8540.oauth.authentication.error.ExceptionTranslator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@Slf4j
public class UserExceptionTranslator implements ExceptionTranslator<ErrorMessage<?>> {

    @Override
    public ResponseEntity<ErrorMessage<?>> translate(Exception exception) {
        if (exception instanceof UserNotFoundException) {
            UserNotFoundException e = ((UserNotFoundException) exception);
            return response(HttpStatus.NOT_FOUND, ErrorMessage.instance(e.getCode(), e.getDescription()));
        } else if (exception instanceof UserRegisterException) {
            UserRegisterException e = ((UserRegisterException) exception);
            return response(HttpStatus.BAD_REQUEST, ErrorMessage.instance(e.getCode(), e.getDescription()));
        } else if (exception instanceof UserInvalidException) {
            UserInvalidException e = ((UserInvalidException) exception);
            return response(HttpStatus.BAD_REQUEST, ErrorMessage.instance(e.getCode(), e.getErrors()));
        } else if (exception instanceof UserAuthorizationException) {
            UserAuthorizationException e = ((UserAuthorizationException) exception);
            return response(HttpStatus.UNAUTHORIZED, ErrorMessage.instance(e.getCode(), e.getDescription()));
        } else {
            if (log.isErrorEnabled()) {
                log.error("Handle exception {} {}", exception.getClass(), exception.getMessage());
            }
            return response(HttpStatus.INTERNAL_SERVER_ERROR, UNKNOWN_SERVER_ERROR);
        }
    }
}
