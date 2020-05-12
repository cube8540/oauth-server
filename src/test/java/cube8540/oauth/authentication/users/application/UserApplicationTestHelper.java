package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.credentials.authority.BasicAuthorityService;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserCredentialsKey;
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.oauth.authentication.users.domain.UserKeyMatchedResult;
import cube8540.oauth.authentication.users.domain.UserRepository;
import cube8540.oauth.authentication.users.domain.UserValidationPolicy;
import cube8540.validator.core.ValidationRule;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UserApplicationTestHelper {

    static final String RAW_EMAIL = "email@email.com";
    static final UserEmail EMAIL = new UserEmail(RAW_EMAIL);

    static final String PASSWORD = "Password1234!@#$";
    static final String NEW_PASSWORD = "NewPassword1234!@#$";
    static final String ENCODED_PASSWORD =  "$2a$10$MrsAcjEPfD4ktbWEb13SBu.lE2OfGWZ2NPqgUoSTeWA7bvh9.k3WC";

    static final String RAW_CREDENTIALS_KEY = "CREDENTIALS-KEY";
    static final String RAW_PASSWORD_CREDENTIALS_KEY = "PASSWORD-CREDENTIALS-KEY";

    static final Set<String> RAW_AUTHORITIES = new HashSet<>(Arrays.asList("CODE-1", "CODE-2", "CODE-3"));
    static final Set<AuthorityCode> AUTHORITIES = RAW_AUTHORITIES.stream().map(AuthorityCode::new).collect(Collectors.toSet());
    static final List<AuthorityCode> BASIC_AUTHORITIES = RAW_AUTHORITIES.stream().map(AuthorityCode::new).collect(Collectors.toList());

    static MockUser mockUser() {
        return new MockUser();
    }

    static MockUser configDefaultMockUser() {
        return mockUser().email()
                .password();
    }

    static MockPasswordEncoder mockPasswordEncoder() {
        return new MockPasswordEncoder();
    }

    static MockUserRepository mockUserRepository() {
        return new MockUserRepository();
    }

    static MockValidationRule<User> mockValidationRule() {
        return new MockValidationRule<>();
    }

    static MockUserValidationPolicy mockValidationPolicy() {
        return new MockUserValidationPolicy();
    }

    static MockCredentialsKey mockCredentialsKey() {
        return new MockCredentialsKey();
    }

    static MockBasicAuthorityService mockBasicAuthorityService() {
        return new MockBasicAuthorityService();
    }

    static UserCredentialsKeyGenerator mockKeyGenerator() {
        UserCredentialsKeyGenerator generator = mock(UserCredentialsKeyGenerator.class);
        when(generator.generateKey()).thenReturn(null);
        return generator;
    }

    static Principal mockPrincipal(String username) {
        Principal principal = mock(Principal.class);

        when(principal.getName()).thenReturn(username);
        return principal;
    }

    static class MockUser {
        private User user;

        private MockUser() {
            this.user = mock(User.class);
        }

        MockUser email() {
            when(user.getEmail()).thenReturn(UserApplicationTestHelper.EMAIL);
            return this;
        }

        MockUser password() {
            when(user.getPassword()).thenReturn(UserApplicationTestHelper.PASSWORD);
            return this;
        }

        MockUser certified() {
            when(user.isCredentials()).thenReturn(true);
            return this;
        }

        MockUser passwordCredentialsKey(UserCredentialsKey key) {
            when(user.getPasswordCredentialsKey()).thenReturn(key);
            return this;
        }

        User build() {
            return user;
        }
    }

    static class MockUserRepository {
        private UserRepository repository;

        private MockUserRepository() {
            this.repository = mock(UserRepository.class);
            doAnswer(returnsFirstArg()).when(repository).save(isA(User.class));
        }

        MockUserRepository emptyUser() {
            when(repository.findByEmail(EMAIL)).thenReturn(Optional.empty());
            return this;
        }

        MockUserRepository registerUser(User user) {
            when(repository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
            return this;
        }

        MockUserRepository countUser(long count) {
            when(repository.countByEmail(EMAIL)).thenReturn(count);
            return this;
        }

        UserRepository build() {
            return repository;
        }
    }

    static class MockPasswordEncoder {
        private PasswordEncoder encoder;

        private MockPasswordEncoder() {
            this.encoder = mock(PasswordEncoder.class);
        }

        MockPasswordEncoder encode() {
            when(encoder.encode(PASSWORD)).thenReturn(ENCODED_PASSWORD);
            return this;
        }

        PasswordEncoder build() {
            return encoder;
        }
    }

    static class MockCredentialsKey {
        private UserCredentialsKey key;

        private MockCredentialsKey() {
            this.key = mock(UserCredentialsKey.class);
        }

        MockCredentialsKey key(String key) {
            when(this.key.getKeyValue()).thenReturn(key);
            return this;
        }

        MockCredentialsKey matches() {
            when(this.key.matches(RAW_PASSWORD_CREDENTIALS_KEY)).thenReturn(UserKeyMatchedResult.MATCHED);
            return this;
        }

        MockCredentialsKey expired() {
            when(this.key.matches(RAW_PASSWORD_CREDENTIALS_KEY)).thenReturn(UserKeyMatchedResult.EXPIRED);
            return this;
        }

        MockCredentialsKey mismatches() {
            when(this.key.matches(RAW_PASSWORD_CREDENTIALS_KEY)).thenReturn(UserKeyMatchedResult.NOT_MATCHED);
            return this;
        }

        UserCredentialsKey build() {
            return key;
        }
    }

    static class MockValidationRule<T> {
        private ValidationRule<T> validationRule;

        @SuppressWarnings("unchecked")
        private MockValidationRule() {
            this.validationRule = mock(ValidationRule.class);
        }

        MockValidationRule<T> configReturnsTrue() {
            when(validationRule.isValid(any())).thenReturn(true);
            return this;
        }

        ValidationRule<T> build() {
            return validationRule;
        }
    }

    static class MockUserValidationPolicy {
        private UserValidationPolicy policy;

        private MockUserValidationPolicy() {
            this.policy = mock(UserValidationPolicy.class);
        }

        MockUserValidationPolicy email(ValidationRule<User> validationRule) {
            when(policy.emailRule()).thenReturn(validationRule);
            return this;
        }

        MockUserValidationPolicy password(ValidationRule<User> validationRule) {
            when(policy.passwordRule()).thenReturn(validationRule);
            return this;
        }

        UserValidationPolicy build() {
            return policy;
        }
    }

    static class MockBasicAuthorityService {
        private BasicAuthorityService service;

        private MockBasicAuthorityService() {
            this.service = mock(BasicAuthorityService.class);
        }

        MockBasicAuthorityService basicAuthority() {
            when(service.getBasicAuthority()).thenReturn(BASIC_AUTHORITIES);
            return this;
        }

        BasicAuthorityService build() {
            return service;
        }
    }

    static Set<GrantedAuthority> convertGrantAuthority(Collection<AuthorityCode> authorities) {
        return authorities.stream()
                .map(AuthorityCode::getValue)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
    }
}
