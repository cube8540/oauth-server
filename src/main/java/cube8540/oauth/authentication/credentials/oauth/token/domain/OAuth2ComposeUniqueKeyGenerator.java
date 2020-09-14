package cube8540.oauth.authentication.credentials.oauth.token.domain;

public interface OAuth2ComposeUniqueKeyGenerator {

    OAuth2ComposeUniqueKey generateKey(OAuth2AuthorizedAccessToken token);

}
