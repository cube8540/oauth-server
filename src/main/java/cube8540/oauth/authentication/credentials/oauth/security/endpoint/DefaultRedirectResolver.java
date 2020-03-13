package cube8540.oauth.authentication.credentials.oauth.security.endpoint;

import cube8540.oauth.authentication.credentials.oauth.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.error.RedirectMismatchException;

import java.net.URI;

public class DefaultRedirectResolver implements RedirectResolver {
    @Override
    public URI resolveRedirectURI(String redirectURI, OAuth2ClientDetails clientDetails) {
        if (redirectURI == null && clientDetails.getRegisteredRedirectUris().size() == 1) {
            return clientDetails.getRegisteredRedirectUris().iterator().next();
        }
        if (redirectURI == null) {
            throw InvalidRequestException.invalidRequest("redirect uri is required");
        }
        URI requestingURI = URI.create(redirectURI);
        if (clientDetails.getRegisteredRedirectUris().contains(requestingURI)) {
            return requestingURI;
        } else {
            throw new RedirectMismatchException(redirectURI + " is not registered");
        }
    }
}
