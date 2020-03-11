package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.domain.Authority;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityRepository;
import cube8540.oauth.authentication.credentials.authority.domain.ResourceMethod;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResource;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceId;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceRepository;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceValidationPolicy;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;

import java.net.URI;
import java.util.Optional;

import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthorityApplicationTestHelper {

    static final String RAW_CODE = "AUTHORITY-CODE";
    static final AuthorityCode CODE = new AuthorityCode(RAW_CODE);

    static final String DESCRIPTION = "DESCRIPTION";
    static final String MODIFY_DESCRIPTION = "MODIFY-DESCRIPTION";

    static final String RAW_RESOURCE_ID = "RESOURCE-ID";
    static final SecuredResourceId RESOURCE_ID = new SecuredResourceId(RAW_RESOURCE_ID);

    static final String RAW_RESOURCE_URI = "/resource/**";
    static final URI RESOURCE_URI = URI.create(RAW_RESOURCE_URI);

    static MockAuthorityRepository mockAuthorityRepository() {
        return new MockAuthorityRepository();
    }

    static MockAuthority configDefaultAuthority() {
        return mockAuthority().code().description();
    }

    static MockAuthority mockAuthority() {
        return new MockAuthority();
    }

    static MockResourceRepository mockResourceRepository() {
        return new MockResourceRepository();
    }

    static MockSecuredResource mockSecuredResource() {
        return new MockSecuredResource();
    }

    static MockValidationRule<SecuredResource> mockResourceValidationRule() {
        return new MockValidationRule<>();
    }

    static MockResourceValidationPolicy mockResourceValidationPolicy() {
        return new MockResourceValidationPolicy();
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

    final static class MockSecuredResource {
        private SecuredResource resource;

        private MockSecuredResource() {
            this.resource = mock(SecuredResource.class);
        }

        MockSecuredResource resourceId() {
            when(resource.getResourceId()).thenReturn(RESOURCE_ID);
            return this;
        }

        MockSecuredResource resource() {
            when(resource.getResource()).thenReturn(RESOURCE_URI);
            return this;
        }

        MockSecuredResource method() {
            when(resource.getMethod()).thenReturn(ResourceMethod.ALL);
            return this;
        }

        SecuredResource build() {
            return resource;
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

    final static class MockResourceRepository {
        private SecuredResourceRepository repository;

        private MockResourceRepository() {
            this.repository = mock(SecuredResourceRepository.class);

            doAnswer(returnsFirstArg()).when(repository).save(isA(SecuredResource.class));
        }

        MockResourceRepository emptyResource() {
            when(repository.findById(RESOURCE_ID)).thenReturn(Optional.empty());
            when(repository.countByResourceId(RESOURCE_ID)).thenReturn(0L);
            return this;
        }

        MockResourceRepository registerResource(SecuredResource resource) {
            when(repository.findById(RESOURCE_ID)).thenReturn(Optional.of(resource));
            when(repository.countByResourceId(RESOURCE_ID)).thenReturn(1L);
            return this;
        }

        SecuredResourceRepository build() {
            return repository;
        }
    }

    static final class MockValidationRule<T> {
        private ValidationRule<T> rule;

        @SuppressWarnings("unchecked")
        private MockValidationRule() {
            this.rule = mock(ValidationRule.class);
        }

        MockValidationRule<T> configReturnTrue() {
            when(this.rule.isValid(any())).thenReturn(true);
            return this;
        }

        MockValidationRule<T> configReturnFalse() {
            when(this.rule.isValid(any())).thenReturn(false);
            return this;
        }

        MockValidationRule<T> validationError(ValidationError error) {
            when(this.rule.error()).thenReturn(error);
            return this;
        }

        ValidationRule<T> build() {
            return rule;
        }
    }

    static final class MockResourceValidationPolicy {
        private SecuredResourceValidationPolicy policy;

        private MockResourceValidationPolicy() {
            this.policy = mock(SecuredResourceValidationPolicy.class);
        }

        MockResourceValidationPolicy resourceIdRule(ValidationRule<SecuredResource> validationRule) {
            when(this.policy.resourceIdRule()).thenReturn(validationRule);
            return this;
        }

        MockResourceValidationPolicy resourceRule(ValidationRule<SecuredResource> validationRule) {
            when(this.policy.resourceRule()).thenReturn(validationRule);
            return this;
        }

        MockResourceValidationPolicy methodRule(ValidationRule<SecuredResource> validationRule) {
            when(this.policy.methodRule()).thenReturn(validationRule);
            return this;
        }

        SecuredResourceValidationPolicy build() {
            return policy;
        }
    }
}
