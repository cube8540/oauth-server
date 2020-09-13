package cube8540.oauth.authentication.credentials.oauth.scope.application;

import cube8540.oauth.authentication.credentials.AuthorityCode;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeRepository;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeValidatorFactory;
import cube8540.validator.core.ValidationResult;
import cube8540.validator.core.Validator;

import java.util.Optional;

import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ScopeApplicationTestHelper {

    static final String RAW_SCOPE_ID = "SCOPE-ID";
    static final AuthorityCode SCOPE_ID = new AuthorityCode(RAW_SCOPE_ID);

    static final String DESCRIPTION = "DESCRIPTION";
    static final String NEW_DESCRIPTION = "NEW-DESCRIPTION";

    static final Boolean SECURED = false;
    static final Boolean MODIFY_SECURED = true;

    static OAuth2Scope makeScope() {
        OAuth2Scope scope = mock(OAuth2Scope.class);

        when(scope.getCode()).thenReturn(SCOPE_ID);
        when(scope.getDescription()).thenReturn(DESCRIPTION);
        when(scope.isSecured()).thenReturn(SECURED);

        return scope;
    }

    static OAuth2ScopeRepository makeEmptyScopeRepository() {
        OAuth2ScopeRepository repository = mock(OAuth2ScopeRepository.class);

        doAnswer(returnsFirstArg()).when(repository).save(isA(OAuth2Scope.class));

        return repository;
    }

    static OAuth2ScopeRepository makeScopeRepository(AuthorityCode code, OAuth2Scope scope) {
        OAuth2ScopeRepository repository = mock(OAuth2ScopeRepository.class);

        when(repository.countByCode(code)).thenReturn(1L);
        when(repository.findById(code)).thenReturn(Optional.of(scope));
        doAnswer(returnsFirstArg()).when(repository).save(isA(OAuth2Scope.class));

        return repository;
    }

    @SuppressWarnings("unchecked")
    static OAuth2ScopeValidatorFactory makeValidatorFactory() {
        OAuth2ScopeValidatorFactory factory = mock(OAuth2ScopeValidatorFactory.class);
        ValidationResult result = mock(ValidationResult.class);
        Validator<OAuth2Scope> validator = mock(Validator.class);

        when(validator.getResult()).thenReturn(result);
        when(factory.createValidator(any())).thenReturn(validator);

        return factory;
    }

    @SuppressWarnings("unchecked")
    static OAuth2ScopeValidatorFactory makeErrorValidatorFactory(Exception exception) {
        OAuth2ScopeValidatorFactory factory = mock(OAuth2ScopeValidatorFactory.class);
        ValidationResult result = mock(ValidationResult.class);
        Validator<OAuth2Scope> validator = mock(Validator.class);

        when(validator.getResult()).thenReturn(result);
        doAnswer(invocation -> {throw exception;}).when(result).hasErrorThrows(any());
        when(factory.createValidator(any())).thenReturn(validator);

        return factory;
    }
}
