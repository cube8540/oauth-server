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

    public static Set<String> extractScopes(String value) {
        Set<String> result = new HashSet<>();
        if (value != null && value.trim().length() > 0) {
            String[] scopes = value.split("[\\s+]");
            result.addAll(Arrays.asList(scopes));
        }
        return result;
    }

}
