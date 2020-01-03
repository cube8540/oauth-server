package cube8540.oauth.authentication.credentials.oauth.client.domain;

import lombok.EqualsAndHashCode;
import lombok.ToString;

import javax.persistence.Embeddable;
import javax.persistence.Transient;

@ToString
@EqualsAndHashCode
@Embeddable
public class OAuth2ClientDefaultSecret implements OAuth2ClientSecret {

    private String secret;

    @Transient
    private boolean encrypted;

    /**
     * JPA/Hibernate에 의해 사용되는 생성자
     */
    protected OAuth2ClientDefaultSecret() {
        this("", true);
    }

    public OAuth2ClientDefaultSecret(String secret) {
        this(secret, false);
    }

    private OAuth2ClientDefaultSecret(String secret, boolean encrypted) {
        this.secret = secret;
        this.encrypted = encrypted;
    }

    @Override
    public String getSecret() {
        return secret;
    }

    @Override
    public boolean isEncrypted() {
        return encrypted;
    }

    @Override
    public OAuth2ClientSecret encrypted(OAuth2ClientSecretEncoder encoder) {
        return new OAuth2ClientDefaultSecret(encoder.encoding(secret), true);
    }
}
