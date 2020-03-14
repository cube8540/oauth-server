package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.authority.domain.ResourceMethod;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResource;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceId;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceRepository;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceValidationPolicy;
import cube8540.oauth.authentication.credentials.authority.domain.exception.ResourceNotFoundException;
import cube8540.oauth.authentication.credentials.authority.domain.exception.ResourceRegisterException;
import lombok.Setter;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class DefaultSecuredResourceManagementService implements SecuredResourceManagementService {

    private final SecuredResourceRepository repository;

    @Setter
    private SecuredResourceValidationPolicy policy;

    public DefaultSecuredResourceManagementService(SecuredResourceRepository repository) {
        this.repository = repository;
    }

    @Override
    public Long count(String resourceId) {
        return repository.countByResourceId(new SecuredResourceId(resourceId));
    }

    @Override
    public List<SecuredResourceDetails> getResources() {
        return repository.findAll().stream().map(DefaultSecuredResourceDetails::of).collect(Collectors.toList());
    }

    @Override
    public SecuredResourceDetails registerNewResource(SecuredResourceRegisterRequest registerRequest) {
        if (repository.countByResourceId(new SecuredResourceId(registerRequest.getResourceId())) > 0) {
            throw ResourceRegisterException.existsIdentifier(registerRequest.getResourceId() + " is already exists");
        }
        SecuredResource resource = new SecuredResource(new SecuredResourceId(registerRequest.getResourceId()),
                URI.create(registerRequest.getResource()), ResourceMethod.of(registerRequest.getMethod()));
        Optional.ofNullable(registerRequest.getAuthorities()).orElse(Collections.emptyList())
                .stream().map(AuthorityCode::new).forEach(resource::addAuthority);
        resource.validation(policy);
        return DefaultSecuredResourceDetails.of(repository.save(resource));
    }

    @Override
    public SecuredResourceDetails modifyResource(String resourceId, SecuredResourceModifyRequest modifyRequest) {
        SecuredResource resource = getResource(resourceId);
        resource.changeResourceInfo(URI.create(modifyRequest.getResource()), ResourceMethod.of(modifyRequest.getMethod()));
        Optional.ofNullable(modifyRequest.getRemoveAuthorities()).orElse(Collections.emptyList())
                .stream().map(AuthorityCode::new).forEach(resource::removeAuthority);
        Optional.ofNullable(modifyRequest.getNewAuthorities()).orElse(Collections.emptyList())
                .stream().map(AuthorityCode::new).forEach(resource::addAuthority);
        resource.validation(policy);
        return DefaultSecuredResourceDetails.of(repository.save(resource));
    }

    @Override
    public SecuredResourceDetails removeResource(String resourceId) {
        SecuredResource resource = getResource(resourceId);

        repository.delete(resource);
        return DefaultSecuredResourceDetails.of(resource);
    }

    private SecuredResource getResource(String resourceId) {
        return repository.findById(new SecuredResourceId(resourceId))
                .orElseThrow(() -> ResourceNotFoundException.instance(resourceId + " is not found"));
    }
}
