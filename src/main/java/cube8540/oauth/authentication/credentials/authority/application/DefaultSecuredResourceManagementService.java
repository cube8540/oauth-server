package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.domain.ResourceMethod;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResource;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceId;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceRepository;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceValidationPolicy;
import cube8540.oauth.authentication.credentials.authority.error.ResourceNotFoundException;
import cube8540.oauth.authentication.credentials.authority.error.ResourceRegisterException;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class DefaultSecuredResourceManagementService implements SecuredResourceManagementService {

    private final SecuredResourceRepository repository;

    @Setter
    private SecuredResourceValidationPolicy policy;

    @Autowired
    public DefaultSecuredResourceManagementService(SecuredResourceRepository repository) {
        this.repository = repository;
    }

    @Override
    public List<SecuredResourceDetails> getResources() {
        return repository.findAll().stream().map(SecuredResourceDetails::of).collect(Collectors.toList());
    }

    @Override
    public SecuredResourceDetails registerNewResource(SecuredResourceRegisterRequest registerRequest) {
        if (repository.countByResourceId(new SecuredResourceId(registerRequest.getResourceId())) > 0) {
            throw ResourceRegisterException.existsIdentifier(registerRequest.getResourceId() + " is already exists");
        }
        SecuredResource resource = new SecuredResource(new SecuredResourceId(registerRequest.getResourceId()),
                URI.create(registerRequest.getResource()), ResourceMethod.of(registerRequest.getMethod()));
        resource.validation(policy);
        return SecuredResourceDetails.of(repository.save(resource));
    }

    @Override
    public SecuredResourceDetails modifyResource(String resourceId, SecuredResourceModifyRequest modifyRequest) {
        SecuredResource resource = getResource(resourceId);
        resource.changeResourceInfo(URI.create(modifyRequest.getResource()), ResourceMethod.of(modifyRequest.getMethod()));
        resource.validation(policy);
        return SecuredResourceDetails.of(repository.save(resource));
    }

    @Override
    public SecuredResourceDetails removeResource(String resourceId) {
        SecuredResource resource = getResource(resourceId);

        repository.delete(resource);
        return SecuredResourceDetails.of(resource);
    }

    private SecuredResource getResource(String resourceId) {
        return repository.findById(new SecuredResourceId(resourceId))
                .orElseThrow(() -> ResourceNotFoundException.instance(resourceId + " is not found"));
    }
}
