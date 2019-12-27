package cube8540.oauth.authentication.credentials.oauth.client.domain;

public enum OAuth2ClientGrantType {

    AUTHORIZATION_CODE("authorization_code"),
    REFRESH_TOKEN("refresh_token"),
    IMPLICIT("implicit"),
    RESOURCE_OWNER_PASSWORD_CREDENTIALS("password"),
    CLIENT_CREDENTIALS("client_credentials");

    private final String grantName;

    OAuth2ClientGrantType(String grantName) {
        this.grantName = grantName;
    }

    public String getGrantName() {
        return grantName;
    }

    public static OAuth2ClientGrantType grantNameOf(String grantName) {
        for (OAuth2ClientGrantType grantType : OAuth2ClientGrantType.values()) {
            if (grantType.getGrantName().equals(grantName)) {
                return grantType;
            }
        }

        throw new IllegalArgumentException(grantName);
    }
}
