package cube8540.oauth.authentication.credentials.oauth.token.domain.exception;

import cube8540.oauth.authentication.error.message.ErrorCodes;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class TokenAccessDeniedException extends RuntimeException {

    private final String code;
    private final String description;

    public static TokenAccessDeniedException denied(String description) {
        return new TokenAccessDeniedException(ErrorCodes.ACCESS_DENIED, description);
    }

}
