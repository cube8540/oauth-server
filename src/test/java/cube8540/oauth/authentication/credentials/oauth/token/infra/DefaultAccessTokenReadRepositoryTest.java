package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.oauth.token.domain.AccessTokenDetailsWithClient;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import java.util.ArrayList;
import java.util.List;

import static cube8540.oauth.authentication.credentials.oauth.token.infra.DefaultAccessTokenReadRepository.ACCESS_TOKEN_WITH_CLIENT_BY_USERNAME_QUERY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 검색 리파지토리 테스트")
class DefaultAccessTokenReadRepositoryTest {

    private static final String RAW_USERNAME = "username";

    @Test
    @DisplayName("액세스 토큰, 클라이언트 검색")
    @SuppressWarnings("unchecked")
    void getAccessTokenDetailsWithClient() {
        List<AccessTokenDetailsWithClient> tokens = new ArrayList<>();
        TypedQuery<AccessTokenDetailsWithClient> typedQuery = mock(TypedQuery.class);
        EntityManager entityManager = mock(EntityManager.class);
        DefaultAccessTokenReadRepository repository = new DefaultAccessTokenReadRepository(entityManager);

        when(entityManager.createQuery(ACCESS_TOKEN_WITH_CLIENT_BY_USERNAME_QUERY, AccessTokenDetailsWithClient.class)).thenReturn(typedQuery);
        when(typedQuery.setParameter(eq("username"), any())).thenReturn(typedQuery);
        when(typedQuery.getResultList()).thenReturn(tokens);

        List<AccessTokenDetailsWithClient> result = repository.readAccessTokenWithClientByUsername(RAW_USERNAME);
        assertEquals(tokens, result);
    }
}