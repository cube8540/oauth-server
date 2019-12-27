package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.domain.Authority;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 권한 서비스 테스트")
class DefaultAuthorityServiceTest {

    private AuthorityRepository repository;
    private DefaultAuthorityService service;

    @BeforeEach
    void setup() {
        this.repository = mock(AuthorityRepository.class);
        this.service = new DefaultAuthorityService(repository);
    }

    @Nested
    @DisplayName("기본 권한 찾기")
    class FindBasicAuthority {
        private List<Authority> authorities;

        @BeforeEach
        void setup() {
            this.authorities = Arrays.asList(mock(Authority.class), mock(Authority.class), mock(Authority.class));
            when(repository.findByBasicTrue()).thenReturn(this.authorities);
        }

        @Test
        @DisplayName("저장소에서 반환된 권한을 반환 해야한다.")
        void shouldReturnsRepositoryAuthority() {
            List<Authority> result = service.getBasicAuthority();
            assertEquals(authorities, result);
        }
    }

}