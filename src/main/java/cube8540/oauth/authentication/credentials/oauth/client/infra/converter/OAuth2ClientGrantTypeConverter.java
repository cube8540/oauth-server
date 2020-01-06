package cube8540.oauth.authentication.credentials.oauth.client.infra.converter;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

import javax.persistence.AttributeConverter;

public class OAuth2ClientGrantTypeConverter implements AttributeConverter<AuthorizationGrantType, String> {
    @Override
    public String convertToDatabaseColumn(AuthorizationGrantType attribute) {
        return attribute.getValue();
    }

    @Override
    public AuthorizationGrantType convertToEntityAttribute(String dbData) {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(dbData)) {
            return AuthorizationGrantType.AUTHORIZATION_CODE;
        } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(dbData)) {
            return AuthorizationGrantType.CLIENT_CREDENTIALS;
        } else if (AuthorizationGrantType.IMPLICIT.getValue().equals(dbData)) {
            return AuthorizationGrantType.IMPLICIT;
        } else if (AuthorizationGrantType.PASSWORD.getValue().equals(dbData)) {
            return AuthorizationGrantType.PASSWORD;
        } else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(dbData)) {
            return AuthorizationGrantType.PASSWORD;
        } else {
            throw new IllegalArgumentException(dbData + " invalid grant type");
        }
    }
}
