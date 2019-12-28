package cube8540.oauth.authentication.credentials.oauth.client.converter;

import cube8540.oauth.authentication.credentials.oauth.OAuth2GrantType;

import javax.persistence.AttributeConverter;

public class OAuth2ClientGrantTypeConverter implements AttributeConverter<OAuth2GrantType, String> {
    @Override
    public String convertToDatabaseColumn(OAuth2GrantType attribute) {
        return attribute.getGrantName();
    }

    @Override
    public OAuth2GrantType convertToEntityAttribute(String dbData) {
        return OAuth2GrantType.grantNameOf(dbData);
    }
}
