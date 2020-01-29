package cube8540.oauth.authentication.credentials.oauth.code.application;

import cube8540.oauth.authentication.credentials.oauth.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.code.domain.AuthorizationCode;
import cube8540.oauth.authentication.credentials.oauth.code.domain.AuthorizationCodeGenerator;
import cube8540.oauth.authentication.credentials.oauth.code.domain.AuthorizationCodeRepository;
import cube8540.oauth.authentication.credentials.oauth.code.domain.OAuth2AuthorizationCode;
import cube8540.oauth.authentication.credentials.oauth.code.infra.DefaultAuthorizationCodeGenerator;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class DefaultAuthorizationCodeService implements OAuth2AuthorizationCodeService {

    private final AuthorizationCodeRepository codeRepository;

    @Setter
    private AuthorizationCodeGenerator codeGenerator = new DefaultAuthorizationCodeGenerator();

    @Setter
    private Duration codeDuration = Duration.ofMinutes(1);

    @Autowired
    public DefaultAuthorizationCodeService(AuthorizationCodeRepository codeRepository) {
        this.codeRepository = codeRepository;
    }

    @Override
    public Optional<OAuth2AuthorizationCode> consume(AuthorizationCode code) {
        Optional<OAuth2AuthorizationCode> authorizationCode = codeRepository.findById(code);
        authorizationCode.ifPresent(codeRepository::delete);

        return authorizationCode;
    }

    @Override
    public AuthorizationCode generateNewAuthorizationCode(AuthorizationRequest request) {
        LocalDateTime expiration = LocalDateTime.now().plus(codeDuration).withNano(0);
        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(codeGenerator, expiration);

        authorizationCode.setAuthorizationRequest(request);
        codeRepository.save(authorizationCode);

        return authorizationCode.getCode();
    }
}
