package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.domain.Authority;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityRepository;

import java.util.Optional;

import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthorityApplicationTestHelper {

    static final String RAW_CODE = "AUTHORITY-CODE";
    static final AuthorityCode CODE = new AuthorityCode(RAW_CODE);

    static final String DESCRIPTION = "DESCRIPTION";
    static final String MODIFY_DESCRIPTION = "MODIFY-DESCRIPTION";

    static MockAuthorityRepository mockAuthorityRepository() {
        return new MockAuthorityRepository();
    }

    static MockAuthority configDefaultAuthority() {
        return mockAuthority().code().description();
    }

    static MockAuthority mockAuthority() {
        return new MockAuthority();
    }

    final static class MockAuthority {
        private Authority authority;

        private MockAuthority() {
            this.authority = mock(Authority.class);
        }

        MockAuthority code() {
            when(authority.getCode()).thenReturn(CODE);
            return this;
        }

        MockAuthority description() {
            when(authority.getDescription()).thenReturn(DESCRIPTION);
            return this;
        }

        Authority build() {
            return authority;
        }
    }

    final static class MockAuthorityRepository {
        private AuthorityRepository repository;

        private MockAuthorityRepository() {
            this.repository = mock(AuthorityRepository.class);

            doAnswer(returnsFirstArg()).when(repository).save(isA(Authority.class));
        }

        MockAuthorityRepository count(long count) {
            when(repository.countByCode(CODE)).thenReturn(count);
            return this;
        }

        MockAuthorityRepository emptyAuthority() {
            when(repository.findById(CODE)).thenReturn(Optional.empty());
            return this;
        }

        MockAuthorityRepository registerAuthority(Authority authority) {
            when(repository.findById(CODE)).thenReturn(Optional.of(authority));
            return this;
        }

        AuthorityRepository build() {
            return repository;
        }
    }
}
