package cube8540.oauth.authentication.credentials.oauth.converter;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientGrantType;

import javax.persistence.AttributeConverter;

public class OAuth2GrantTypeConverter implements AttributeConverter<OAuth2ClientGrantType, String> {
    @Override
    public String convertToDatabaseColumn(OAuth2ClientGrantType attribute) {
        return attribute.getGrantName();
    }

    @Override
    public OAuth2ClientGrantType convertToEntityAttribute(String dbData) {
        return OAuth2ClientGrantType.grantNameOf(dbData);
    }
}
