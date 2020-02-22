package cube8540.oauth.authentication.credentials.oauth.client.endpoint;

import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ChangeSecretRequest;
import cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientManagementService;
import cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientModifyRequest;
import cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientRegisterRequest;
import cube8540.oauth.authentication.credentials.oauth.client.error.ClientExceptionTranslator;
import cube8540.oauth.authentication.error.ErrorMessage;
import cube8540.oauth.authentication.message.ResponseMessage;
import cube8540.oauth.authentication.message.SuccessResponseMessage;
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

@RestController
public class ClientManagementAPIEndpoint {

    private static final int DEFAULT_CLIENT_PAGE_SIZE = 10;

    private final OAuth2ClientManagementService service;

    @Setter
    private ClientExceptionTranslator translator = new ClientExceptionTranslator();

    @Setter
    private int clientPageSize;

    @Autowired
    public ClientManagementAPIEndpoint(@Qualifier("clientManagementService") OAuth2ClientManagementService service) {
        this.service = service;
        this.clientPageSize = DEFAULT_CLIENT_PAGE_SIZE;
    }

    @GetMapping(value = "/api/clients/attributes/{clientId}")
    public ResponseEntity<ResponseMessage> countClientId(@PathVariable("clientId") String clientId) {
        long count = service.countClient(clientId);

        ResponseMessage message = SuccessResponseMessage.ok(count);
        return new ResponseEntity<>(message, message.getStatus());
    }

    @GetMapping(value = "/api/clients")
    public ResponseEntity<ResponseMessage> clients(@RequestParam(value = "page", required = false) Integer page) {
        Pageable pageable = PageRequest.of(page == null ? 0 : page, clientPageSize);

        Page<OAuth2ClientDetails> clients = service.loadClientDetails(pageable);
        ResponseMessage message = SuccessResponseMessage.ok(clients);
        return new ResponseEntity<>(message, message.getStatus());
    }

    @PostMapping(value = "/api/clients")
    public ResponseEntity<ResponseMessage> registerNewClient(@RequestBody OAuth2ClientRegisterRequest registerRequest) {
        OAuth2ClientDetails client = service.registerNewClient(registerRequest);

        ResponseMessage message = SuccessResponseMessage.ok(client);
        return new ResponseEntity<>(message, message.getStatus());
    }

    @PutMapping(value = "/api/clients/{clientId}")
    public ResponseEntity<ResponseMessage> modifyClient(@PathVariable("clientId") String clientId, @RequestBody OAuth2ClientModifyRequest modifyRequest) {
        OAuth2ClientDetails client = service.modifyClient(clientId, modifyRequest);

        ResponseMessage message = SuccessResponseMessage.ok(client);
        return new ResponseEntity<>(message, message.getStatus());
    }

    @PutMapping(value = "/api/clients/{clientId}/attributes/secret")
    public ResponseEntity<ResponseMessage> changeSecret(@PathVariable("clientId") String clientId, @RequestBody OAuth2ChangeSecretRequest changeRequest) {
        OAuth2ClientDetails client = service.changeSecret(clientId, changeRequest);

        ResponseMessage message = SuccessResponseMessage.ok(client);
        return new ResponseEntity<>(message, message.getStatus());
    }

    @DeleteMapping(value = "/api/clients/{clientId}")
    public ResponseEntity<ResponseMessage> removeClient(@PathVariable("clientId") String clientId) {
        OAuth2ClientDetails client = service.removeClient(clientId);

        ResponseMessage message = SuccessResponseMessage.ok(client);
        return new ResponseEntity<>(message, message.getStatus());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorMessage<?>> handle(Exception e) {
        return translator.translate(e);
    }
}