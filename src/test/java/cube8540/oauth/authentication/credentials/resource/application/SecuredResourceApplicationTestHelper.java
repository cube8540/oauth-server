package cube8540.oauth.authentication.credentials.resource.application;

import cube8540.oauth.authentication.credentials.resource.domain.AccessibleAuthority;
import cube8540.oauth.authentication.credentials.resource.domain.ResourceMethod;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceId;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceRepository;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceValidatorFactory;
import cube8540.validator.core.ValidationResult;
import cube8540.validator.core.Validator;

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
    static final List<AccessibleAuthorityValue> REQUEST_AUTHORITIES = RAW_AUTHORITIES.stream().map(AccessibleAuthorityValue::new).collect(Collectors.toList());
    static final Set<AccessibleAuthority> AUTHORITIES = RAW_AUTHORITIES.stream().map(AccessibleAuthority::new).collect(Collectors.toSet());
    static final List<String> RAW_REMOVE_AUTHORITIES = Arrays.asList("REMOVE-AUTHORITY-1", "REMOVE-AUTHORITY-2", "REMOVE-AUTHORITY-3");
    static final List<String> RAW_ADD_AUTHORITIES = Arrays.asList("ADD-AUTHORITY-1", "ADD-AUTHORITY-2", "ADD-AUTHORITY-3");
    static final List<AccessibleAuthorityValue> REMOVE_REQUEST_AUTHORITIES = RAW_REMOVE_AUTHORITIES.stream().map(AccessibleAuthorityValue::new).collect(Collectors.toList());
    static final List<AccessibleAuthority> REMOVE_AUTHORITIES = RAW_REMOVE_AUTHORITIES.stream().map(AccessibleAuthority::new).collect(Collectors.toList());
    static final List<AccessibleAuthorityValue> ADD_REQUEST_AUTHORITIES = RAW_ADD_AUTHORITIES.stream().map(AccessibleAuthorityValue::new).collect(Collectors.toList());
    static final List<AccessibleAuthority> ADD_AUTHORITIES = RAW_ADD_AUTHORITIES.stream().map(AccessibleAuthority::new).collect(Collectors.toList());

    static SecuredResourceRepository makeEmptyResourceRepository() {
        SecuredResourceRepository repository = mock(SecuredResourceRepository.class);

        doAnswer(returnsFirstArg()).when(repository).save(isA(SecuredResource.class));

        return repository;
    }

    static SecuredResourceRepository makeResourceRepository(SecuredResourceId resourceId, SecuredResource resource) {
        SecuredResourceRepository repository = mock(SecuredResourceRepository.class);

        when(repository.findById(resourceId)).thenReturn(Optional.of(resource));
        when(repository.countByResourceId(resourceId)).thenReturn(1L);
        doAnswer(returnsFirstArg()).when(repository).save(isA(SecuredResource.class));

        return repository;
    }

    static SecuredResource makeDefaultSecuredResource() {
        SecuredResource resource = mock(SecuredResource.class);

        when(resource.getResourceId()).thenReturn(RESOURCE_ID);
        when(resource.getResource()).thenReturn(RESOURCE_URI);
        when(resource.getMethod()).thenReturn(ResourceMethod.ALL);

        return resource;
    }

    @SuppressWarnings("unchecked")
    static SecuredResourceValidatorFactory makeValidatorFactory() {
        SecuredResourceValidatorFactory factory = mock(SecuredResourceValidatorFactory.class);
        ValidationResult result = mock(ValidationResult.class);
        Validator<SecuredResource> validator = mock(Validator.class);

        when(validator.getResult()).thenReturn(result);
        when(factory.createValidator(any())).thenReturn(validator);

        return factory;
    }

    @SuppressWarnings("unchecked")
    static SecuredResourceValidatorFactory makeErrorValidatorFactory(Exception exception) {
        SecuredResourceValidatorFactory factory = mock(SecuredResourceValidatorFactory.class);
        ValidationResult result = mock(ValidationResult.class);
        Validator<SecuredResource> validator = mock(Validator.class);

        when(validator.getResult()).thenReturn(result);
        doAnswer(invocation -> {throw exception;}).when(result).hasErrorThrows(any());
        when(factory.createValidator(any())).thenReturn(validator);

        return factory;
    }
}
