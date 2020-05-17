package cube8540.oauth.authentication.credentials.oauth.token.infra.read;

import cube8540.oauth.authentication.credentials.oauth.token.domain.PrincipalUsername;
import cube8540.oauth.authentication.credentials.oauth.token.domain.read.model.AccessTokenDetailsWithClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import java.util.ArrayList;
import java.util.List;

import static cube8540.oauth.authentication.credentials.oauth.token.infra.read.DefaultAccessTokenReadRepository.ACCESS_TOKEN_WITH_CLIENT_BY_USERNAME_QUERY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("기본 검색 리파지토리 테스트")
class DefaultAccessTokenReadRepositoryTest {

    private static final String RAW_USERNAME = "email@email.com";
    private static final PrincipalUsername USERNAME = new PrincipalUsername(RAW_USERNAME);

    @Nested
    @DisplayName("엑세스 토큰, 클라이언트 검색")
    class GetAccessTokenDetailsWithClient {
        private List<AccessTokenDetailsWithClient> tokens;
        private TypedQuery<AccessTokenDetailsWithClient> typedQuery;
        private DefaultAccessTokenReadRepository repository;

        @BeforeEach
        @SuppressWarnings("unchecked")
        void setup() {
            EntityManager entityManager = mock(EntityManager.class);

            this.tokens = new ArrayList<>();
            this.typedQuery = mock(TypedQuery.class);

            when(entityManager.createQuery(ACCESS_TOKEN_WITH_CLIENT_BY_USERNAME_QUERY, AccessTokenDetailsWithClient.class)).thenReturn(typedQuery);
            when(typedQuery.setParameter(eq("username"), any())).thenReturn(typedQuery);
            when(typedQuery.getResultList()).thenReturn(tokens);

            this.repository = new DefaultAccessTokenReadRepository(entityManager);
        }

        @Test
        @DisplayName("입력 받은 유저 명으로 토큰과 클라이언트를 검색하는 쿼리를 실행해야 한다.")
        void shouldQueryingAccessTokenWithClientByUsername() {
            repository.readAccessTokenWithClientByUsername(RAW_USERNAME);

            verify(typedQuery, times(1)).setParameter("username", USERNAME);
        }

        @Test
        @DisplayName("검색된 결과를 반환해야 한다.")
        void shouldReturnsSearchResult() {
            List<AccessTokenDetailsWithClient> result = repository.readAccessTokenWithClientByUsername(RAW_USERNAME);

            assertEquals(tokens, result);
        }
    }

}