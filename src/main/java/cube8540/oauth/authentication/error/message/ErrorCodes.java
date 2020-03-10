package cube8540.oauth.authentication.error.message;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ErrorCodes {

    public static final String NOT_FOUND = "not_found";

    public static final String EXISTS_IDENTIFIER = "exists_identifier";

    public static final String INVALID_REQUEST = "invalid_request";

    public static final String SERVER_ERROR = "server_error";

}
