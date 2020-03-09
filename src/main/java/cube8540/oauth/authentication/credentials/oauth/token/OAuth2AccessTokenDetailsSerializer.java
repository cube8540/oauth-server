package cube8540.oauth.authentication.credentials.oauth.token;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;

import java.io.IOException;
import java.util.Map;
import java.util.stream.Collectors;

public class OAuth2AccessTokenDetailsSerializer extends StdSerializer<OAuth2AccessTokenDetails> {

    public OAuth2AccessTokenDetailsSerializer() {
        super(OAuth2AccessTokenDetails.class);
    }

    @Override
    public void serialize(OAuth2AccessTokenDetails value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        gen.writeStartObject();
        gen.writeStringField(OAuth2Utils.AccessTokenSerializeKey.ACCESS_TOKEN, value.getTokenValue());
        gen.writeStringField(OAuth2Utils.AccessTokenSerializeKey.TOKEN_TYPE, value.getTokenType());
        gen.writeNumberField(OAuth2Utils.AccessTokenSerializeKey.EXPIRES_IN, value.getExpiresIn());
        writeScopeField(value, gen);
        writeRefreshTokenField(value, gen);
        writeAdditionalInformationField(value, gen);
        gen.writeEndObject();
    }

    private void writeAdditionalInformationField(OAuth2AccessTokenDetails value, JsonGenerator gen) throws IOException {
        Map<String, String> additionalInformation = value.getAdditionalInformation();
        if (additionalInformation != null) {
            for (String key : additionalInformation.keySet()) {
                gen.writeStringField(key, additionalInformation.get(key));
            }
        }
    }

    private void writeRefreshTokenField(OAuth2AccessTokenDetails value, JsonGenerator gen) throws IOException {
        if (value.getRefreshToken() != null) {
            gen.writeStringField(OAuth2Utils.AccessTokenSerializeKey.REFRESH_TOKEN, value.getRefreshToken().getTokenValue());
        }
    }

    private void writeScopeField(OAuth2AccessTokenDetails value, JsonGenerator gen) throws IOException {
        String scope = value.getScopes().stream().map(OAuth2ScopeId::getValue).collect(Collectors.joining(" "));
        gen.writeStringField(OAuth2Utils.AccessTokenSerializeKey.SCOPE, scope);
    }
}
