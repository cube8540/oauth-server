package cube8540.oauth.authentication.credentials.oauth.token.domain;

public interface OAuth2TokenEnhancer {

    void enhance(OAuth2AuthorizedAccessToken accessToken);

}
