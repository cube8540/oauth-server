package cube8540.oauth.authentication.credentials.oauth;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class OAuth2Utils {

    @NoArgsConstructor(access = AccessLevel.PRIVATE)
    public static final class TokenRequestKey {
        public static final String GRANT_TYPE = "grant_type";

        public static final String USERNAME = "username";

        public static final String PASSWORD = "password";

        public static final String CLIENT_ID = "client_id";

        public static final String REFRESH_TOKEN = "refresh_token";

        public static final String CODE = "code";

        public static final String REDIRECT_URI = "redirect_uri";

        public static final String SCOPE = "scope";
    }

    @NoArgsConstructor(access = AccessLevel.PRIVATE)
    public static final class AuthorizationRequestKey {
        public static final String CLIENT_ID = "client_id";

        public static final String STATE = "state";

        public static final String REDIRECT_URI = "redirect_uri";

        public static final String SCOPE = "scope";

        public static final String RESPONSE_TYPE = "response_type";
    }

    @NoArgsConstructor(access = AccessLevel.PRIVATE)
    public static final class AuthorizationResponseKey {
        public static final String CODE = "code";

        public static final String STATE = "state";
    }

    @NoArgsConstructor(access = AccessLevel.PRIVATE)
    public static final class AccessTokenSerializeKey {
        public static final String ACCESS_TOKEN = "access_token";

        public static final String TOKEN_TYPE = "token_type";

        public static final String EXPIRES_IN = "expires_in";

        public static final String REFRESH_TOKEN = "refresh_token";

        public static final String SCOPE = "scope";
    }

    @NoArgsConstructor(access = AccessLevel.PRIVATE)
    public static final class AccessTokenIntrospectionKey {
        public static final String ACTIVE = "active";

        public static final String SCOPE = "scope";

        public static final String CLIENT_ID = "client_id";

        public static final String USERNAME = "username";

        public static final String EXPIRATION = "exp";
    }

    public static Set<String> extractScopes(String value) {
        Set<String> result = new HashSet<>();
        if (value != null && value.trim().length() > 0) {
            String[] scopes = value.split("[\\s+]");
            result.addAll(Arrays.asList(scopes));
        }
        return result;
    }

}
