package cube8540.oauth.authentication.credentials.role.application;

import cube8540.oauth.authentication.credentials.AuthorityDetails;
import cube8540.oauth.authentication.credentials.BasicAuthorityDetailsService;
import cube8540.oauth.authentication.credentials.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.role.domain.Role;
import cube8540.oauth.authentication.credentials.role.domain.RoleRepository;
import cube8540.oauth.authentication.credentials.role.domain.exception.RoleNotFoundException;
import cube8540.oauth.authentication.credentials.role.domain.exception.RoleRegisterException;
import cube8540.oauth.authentication.credentials.role.infra.RoleValidationPolicy;
import lombok.Setter;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class DefaultRoleManagementService implements RoleManagementService, BasicAuthorityDetailsService {

    private final RoleRepository repository;

    @Setter
    private RoleValidationPolicy validationPolicy;

    public DefaultRoleManagementService(RoleRepository repository) {
        this.repository = repository;
    }

    @Override
    public Collection<AuthorityDetails> loadBasicAuthorities() {
        return repository.findByBasic(true).stream().map(DefaultRoleDetails::of).collect(Collectors.toList());
    }

    @Override
    public Long countByRoleCode(String code) {
        return repository.countByCode(new AuthorityCode(code));
    }

    @Override
    public List<AuthorityDetails> loadAllAuthorities() {
        return repository.findAll().stream().map(DefaultRoleDetails::of).collect(Collectors.toList());
    }

    @Override
    public AuthorityDetails registerNewRole(RoleRegisterRequest registerRequest) {
        if (repository.countByCode(new AuthorityCode(registerRequest.getCode())) > 0) {
            throw RoleRegisterException.existsIdentifier(registerRequest.getCode() + " is exists");
        }

        Role role = new Role(registerRequest.getCode(), registerRequest.getDescription());
        role.setBasic(registerRequest.isBasic());
        role.validate(validationPolicy);

        return DefaultRoleDetails.of(repository.save(role));
    }

    @Override
    public AuthorityDetails modifyRole(String code, RoleModifyRequest modifyRequest) {
        Role role = repository.findById(new AuthorityCode(code))
                .orElseThrow(() -> RoleNotFoundException.instance(code + " is not found"));

        role.setDescription(modifyRequest.getDescription());
        role.setBasic(modifyRequest.isBasic());
        return DefaultRoleDetails.of(repository.save(role));
    }

    @Override
    public AuthorityDetails removeRole(String code) {
        Role role = repository.findById(new AuthorityCode(code))
                .orElseThrow(() -> RoleNotFoundException.instance(code + " is not found"));

        repository.delete(role);
        return DefaultRoleDetails.of(role);
    }

    @Override
    public Collection<AuthorityDetails> loadAuthorityByAuthorityCodes(Collection<String> authorities) {
        List<AuthorityCode> codeIn = authorities.stream()
                .map(AuthorityCode::new).collect(Collectors.toList());
        return repository.findAllById(codeIn).stream()
                .map(DefaultRoleDetails::of).collect(Collectors.toList());
    }
}
