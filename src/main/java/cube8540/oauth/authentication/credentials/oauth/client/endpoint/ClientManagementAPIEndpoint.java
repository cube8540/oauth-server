package cube8540.oauth.authentication.credentials.oauth.client.endpoint;

import cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ChangeSecretRequest;
import cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientManagementService;
import cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientModifyRequest;
import cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientRegisterRequest;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import cube8540.oauth.authentication.error.ExceptionTranslator;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RestController
public class ClientManagementAPIEndpoint {

    private static final int DEFAULT_CLIENT_PAGE_SIZE = 10;

    private final OAuth2ClientManagementService service;

    @Setter(onMethod_ = {@Autowired, @Qualifier("clientExceptionTranslator")})
    private ExceptionTranslator<ErrorMessage<Object>> translator;

    @Setter
    private int clientPageSize;

    @Autowired
    public ClientManagementAPIEndpoint(@Qualifier("clientManagementService") OAuth2ClientManagementService service) {
        this.service = service;
        this.clientPageSize = DEFAULT_CLIENT_PAGE_SIZE;
    }

    @GetMapping(value = "/api/clients/attributes/clientId")
    public Map<String, Long> countClientId(@RequestParam String clientId) {
        long count = service.countClient(clientId);
        return Collections.singletonMap("count", count);
    }

    @GetMapping(value = "/api/clients")
    public Page<OAuth2ClientDetails> clients(@RequestParam(value = "page", required = false) Integer page) {
        Pageable pageable = PageRequest.of(page == null ? 0 : page, clientPageSize);

        return service.loadClientDetails(pageable);
    }

    @PostMapping(value = "/api/clients")
    public OAuth2ClientDetails registerNewClient(@RequestBody OAuth2ClientRegisterRequest registerRequest) {
        return service.registerNewClient(registerRequest);
    }

    @PutMapping(value = "/api/clients/{clientId}")
    public OAuth2ClientDetails modifyClient(@PathVariable("clientId") String clientId, @RequestBody OAuth2ClientModifyRequest modifyRequest) {
        return service.modifyClient(clientId, modifyRequest);
    }

    @PutMapping(value = "/api/clients/{clientId}/attributes/secret")
    public OAuth2ClientDetails changeSecret(@PathVariable("clientId") String clientId, @RequestBody OAuth2ChangeSecretRequest changeRequest) {
        return service.changeSecret(clientId, changeRequest);
    }

    @DeleteMapping(value = "/api/clients/{clientId}")
    public OAuth2ClientDetails removeClient(@PathVariable("clientId") String clientId) {
        return service.removeClient(clientId);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorMessage<Object>> handle(Exception e) {
        return translator.translate(e);
    }
}