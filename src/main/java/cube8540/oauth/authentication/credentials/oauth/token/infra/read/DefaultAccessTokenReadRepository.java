package cube8540.oauth.authentication.credentials.oauth.token.infra.read;

import cube8540.oauth.authentication.credentials.oauth.token.domain.PrincipalUsername;
import cube8540.oauth.authentication.credentials.oauth.token.domain.read.Oauth2AccessTokenReadRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.read.model.AccessTokenDetailsWithClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import java.util.List;

@Repository
public class DefaultAccessTokenReadRepository implements Oauth2AccessTokenReadRepository {

    protected static final String ACCESS_TOKEN_WITH_CLIENT_BY_USERNAME_QUERY = "select new cube8540.oauth.authentication.credentials.oauth.token.infra.read.model.DefaultAccessTokenDetailsWithClient(token, client)" +
            " from OAuth2AuthorizedAccessToken token, OAuth2Client client" +
            " where token.username = :username and token.client.value = client.clientId.value";

    private final EntityManager entityManager;

    @Autowired
    public DefaultAccessTokenReadRepository(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public List<AccessTokenDetailsWithClient> readAccessTokenWithClientByUsername(String username) {
        return entityManager.createQuery(ACCESS_TOKEN_WITH_CLIENT_BY_USERNAME_QUERY, AccessTokenDetailsWithClient.class)
                .setParameter("username", new PrincipalUsername(username))
                .getResultList();
    }
}
