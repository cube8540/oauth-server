package cube8540.oauth.authentication.credentials.oauth.error;

import cube8540.oauth.authentication.credentials.oauth.AbstractOAuth2AuthenticationException;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.web.HttpRequestMethodNotSupportedException;

public class DefaultOAuth2ExceptionTranslator implements OAuth2ExceptionTranslator {
    @Override
    public ResponseEntity<OAuth2Error> translate(Exception exception) {
        if (exception instanceof AbstractOAuth2AuthenticationException) {
            AbstractOAuth2AuthenticationException authException = ((AbstractOAuth2AuthenticationException) exception);
            return createResponseEntity(authException.getError(), HttpStatus.valueOf(authException.getCode()));
        } else if (exception instanceof HttpRequestMethodNotSupportedException) {
            return createResponseEntity(new OAuth2Error("method_not_allowed"), HttpStatus.METHOD_NOT_ALLOWED);
        } else {
            return createResponseEntity(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private ResponseEntity<OAuth2Error> createResponseEntity(OAuth2Error error, HttpStatus httpStatus) {
        HttpHeaders headers = new HttpHeaders();
        headers.setCacheControl(CacheControl.noStore());
        headers.setPragma("no-cache");

        return new ResponseEntity<>(error, headers, httpStatus);
    }
}
