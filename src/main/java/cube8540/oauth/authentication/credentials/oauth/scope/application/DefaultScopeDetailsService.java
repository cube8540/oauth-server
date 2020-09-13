package cube8540.oauth.authentication.credentials.oauth.scope.application;

import cube8540.oauth.authentication.credentials.AuthorityCode;
import cube8540.oauth.authentication.credentials.AuthorityDetails;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeRepository;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeValidatorFactory;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.exception.ScopeNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.exception.ScopeRegisterException;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class DefaultScopeDetailsService implements OAuth2ScopeManagementService {

    private final OAuth2ScopeRepository repository;

    @Setter(onMethod_ = {@Autowired, @Qualifier("defaultOAuth2ScopeValidatorFactory")})
    private OAuth2ScopeValidatorFactory validatorFactory;

    public DefaultScopeDetailsService(OAuth2ScopeRepository repository) {
        this.repository = repository;
    }

    @Override
    public Collection<AuthorityDetails> loadAuthorityByAuthorityCodes(Collection<String> authorities) {
        List<AuthorityCode> scopeIn = authorities.stream()
                .map(AuthorityCode::new).collect(Collectors.toList());
        return repository.findAllById(scopeIn).stream()
                .map(DefaultOAuth2ScopeDetails::of).collect(Collectors.toList());
    }

    @Override
    public Long countByScopeId(String scopeId) {
        return repository.countByCode(new AuthorityCode(scopeId));
    }

    @Override
    public Collection<AuthorityDetails> loadAllScopes() {
        return repository.findAll().stream().map(DefaultOAuth2ScopeDetails::of).collect(Collectors.toList());
    }

    @Override
    public Collection<AuthorityDetails> loadPublicScopes() {
        return repository.findAll().stream().filter(scope -> !scope.isSecured())
                .map(DefaultOAuth2ScopeDetails::of).collect(Collectors.toList());
    }

    @Override
    @Transactional
    public AuthorityDetails registerNewScope(OAuth2ScopeRegisterRequest registerRequest) {
        if (repository.countByCode(new AuthorityCode(registerRequest.getScopeId())) > 0) {
            throw ScopeRegisterException.existsIdentifier(registerRequest.getScopeId() + " is exists");
        }

        OAuth2Scope scope = new OAuth2Scope(registerRequest.getScopeId(), registerRequest.getDescription());
        scope.setSecured(Optional.ofNullable(registerRequest.getSecured()).orElse(Boolean.TRUE));
        scope.validate(validatorFactory);
        return DefaultOAuth2ScopeDetails.of(repository.save(scope));
    }

    @Override
    @Transactional
    public AuthorityDetails modifyScope(String scopeId, OAuth2ScopeModifyRequest modifyRequest) {
        OAuth2Scope scope = getScope(scopeId);

        scope.setDescription(modifyRequest.getDescription());
        Optional.ofNullable(modifyRequest.getSecured()).ifPresent(scope::setSecured);
        scope.validate(validatorFactory);
        return DefaultOAuth2ScopeDetails.of(repository.save(scope));
    }

    @Override
    @Transactional
    public AuthorityDetails removeScope(String scopeId) {
        OAuth2Scope scope = getScope(scopeId);

        repository.delete(scope);
        return DefaultOAuth2ScopeDetails.of(scope);
    }

    private OAuth2Scope getScope(String scopeId) {
        return repository.findById(new AuthorityCode(scopeId))
                .orElseThrow(() -> ScopeNotFoundException.instance(scopeId));
    }
}
