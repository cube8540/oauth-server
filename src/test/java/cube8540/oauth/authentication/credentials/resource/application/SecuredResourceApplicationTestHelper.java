package cube8540.oauth.authentication.credentials.resource.application;

import cube8540.oauth.authentication.credentials.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.resource.domain.ResourceMethod;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceId;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceRepository;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceValidationPolicy;
import cube8540.validator.core.ValidationRule;

import java.net.URI;
import java.util.Arrays;
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

class SecuredResourceApplicationTestHelper {

    static final String RAW_RESOURCE_ID = "RESOURCE-ID";
    static final SecuredResourceId RESOURCE_ID = new SecuredResourceId(RAW_RESOURCE_ID);

    static final String RAW_RESOURCE_URI = "/resource/**";
    static final URI RESOURCE_URI = URI.create(RAW_RESOURCE_URI);
    static final String RAW_MODIFY_RESOURCE_URI = "/modify-resource/**";
    static final URI MODIFY_RESOURCE_URI = URI.create(RAW_MODIFY_RESOURCE_URI);

    static final List<String> RAW_AUTHORITIES = Arrays.asList("AUTHORITY-1", "AUTHORITY-2", "AUTHORITY-3");
    static final Set<AuthorityCode> AUTHORITIES = RAW_AUTHORITIES.stream().map(AuthorityCode::new).collect(Collectors.toSet());
    static final List<String> RAW_REMOVE_AUTHORITIES = Arrays.asList("REMOVE-AUTHORITY-1", "REMOVE-AUTHORITY-2", "REMOVE-AUTHORITY-3");
    static final List<String> RAW_ADD_AUTHORITIES = Arrays.asList("ADD-AUTHORITY-1", "ADD-AUTHORITY-2", "ADD-AUTHORITY-3");
    static final List<AuthorityCode> REMOVE_AUTHORITIES = RAW_REMOVE_AUTHORITIES.stream().map(AuthorityCode::new).collect(Collectors.toList());
    static final List<AuthorityCode> ADD_AUTHORITIES = RAW_ADD_AUTHORITIES.stream().map(AuthorityCode::new).collect(Collectors.toList());

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

    final static class MockSecuredResource {
        private SecuredResource resource;

        private MockSecuredResource() {
            this.resource = mock(SecuredResource.class);
        }

        MockSecuredResource resourceId() {
            when(resource.getResourceId()).thenReturn(RESOURCE_ID);
            return this;
        }

        MockSecuredResource resourceId(String resourceId) {
            when(resource.getResourceId()).thenReturn(new SecuredResourceId(resourceId));
            return this;
        }

        MockSecuredResource resource() {
            when(resource.getResource()).thenReturn(RESOURCE_URI);
            return this;
        }

        MockSecuredResource resource(URI resource) {
            when(this.resource.getResource()).thenReturn(resource);
            return this;
        }

        MockSecuredResource method() {
            when(resource.getMethod()).thenReturn(ResourceMethod.ALL);
            return this;
        }

        MockSecuredResource method(ResourceMethod method) {
            when(resource.getMethod()).thenReturn(method);
            return this;
        }

        MockSecuredResource authorities(Set<AuthorityCode> authorities) {
            when(resource.getAuthorities()).thenReturn(authorities);
            return this;
        }

        SecuredResource build() {
            return resource;
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

        MockResourceValidationPolicy authoritiesRule(ValidationRule<SecuredResource> validationRule) {
            when(this.policy.authoritiesRule()).thenReturn(validationRule);
            return this;
        }

        SecuredResourceValidationPolicy build() {
            return policy;
        }
    }

}
