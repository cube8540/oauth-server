package cube8540.oauth.authentication.credentials.oauth;

public enum OAuth2GrantType {

    AUTHORIZATION_CODE("authorization_code", true),
    REFRESH_TOKEN("refresh_token", true),
    IMPLICIT("implicit", false),
    RESOURCE_OWNER_PASSWORD_CREDENTIALS("password", true),
    CLIENT_CREDENTIALS("client_credentials", false);

    private final String grantName;
    private final boolean supportRefreshToken;

    OAuth2GrantType(String grantName, boolean supportRefreshToken) {
        this.grantName = grantName;
        this.supportRefreshToken = supportRefreshToken;
    }

    public String getGrantName() {
        return grantName;
    }

    public boolean isSupportRefreshToken() {
        return supportRefreshToken;
    }

    public static OAuth2GrantType grantNameOf(String grantName) {
        for (OAuth2GrantType grantType : OAuth2GrantType.values()) {
            if (grantType.getGrantName().equals(grantName)) {
                return grantType;
            }
        }

        throw new IllegalArgumentException(grantName);
    }
}
