package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.domain.Authority;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
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

        @BeforeEach
        void setup() {
            List<Authority> authorities = Arrays.asList(mocking("CODE-1"), mocking("CODE-2"), mocking("CODE-3"));
            when(repository.findByBasicTrue()).thenReturn(authorities);
        }

        @Test
        @DisplayName("저장소에서 반환된 권한을 반환 해야한다.")
        void shouldReturnsRepositoryAuthority() {
            List<AuthorityCode> result = service.getBasicAuthority();

            List<AuthorityCode> expected = Arrays.asList(new AuthorityCode("CODE-1"),
                    new AuthorityCode("CODE-2"), new AuthorityCode("CODE-3"));
            assertEquals(expected, result);
        }

        private Authority mocking(String code) {
            Authority authority = mock(Authority.class);

            when(authority.getCode()).thenReturn(new AuthorityCode(code));
            return authority;
        }
    }

}