package cube8540.oauth.authentication.rememberme.domain;

import cube8540.oauth.authentication.AuthenticationApplication;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class RememberMeTokenTest {

    private static final LocalDateTime NOW = LocalDateTime.of(2021, 1, 30, 17, 0, 0);
    private static final LocalDateTime NOT_EXPIRATION_DATE_TIME = NOW
            .plusSeconds(RememberMeToken.tokenValiditySeconds)
            .minusNanos(1);
    private static final LocalDateTime EXPIRATION_DATE_TIME = NOW
            .plusSeconds(RememberMeToken.tokenValiditySeconds)
            .plusNanos(1);

    private static final Clock DEFAULT_CLOCK = Clock.fixed(NOW.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
    private static final Clock NOT_EXPIRATION_CLOCK = Clock.fixed(NOT_EXPIRATION_DATE_TIME.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
    private static final Clock EXPIRATION_CLOCK = Clock.fixed(EXPIRATION_DATE_TIME.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());

    private static final String RAW_SERIES_VALUE = "SERIES";
    private static final RememberMeTokenSeries SERIES = new RememberMeTokenSeries(RAW_SERIES_VALUE);

    private static final String RAW_TOKEN_VALUE = "TOKEN";
    private static final RememberMeTokenValue TOKEN_VALUE = new RememberMeTokenValue(RAW_TOKEN_VALUE);

    private static final String RAW_USERNAME = "USERNAME";

    private RememberMeToken token;

    @BeforeEach
    void setup() {
        RememberMeTokenGenerator generator = mock(RememberMeTokenGenerator.class);

        when(generator.generateTokenSeries()).thenReturn(SERIES);
        when(generator.generateTokenValue()).thenReturn(TOKEN_VALUE);

        this.token = new RememberMeToken(generator, RAW_USERNAME);
    }

    @Test
    @DisplayName("토큰 만료일이 지나지 않았을시")
    void tokenNotExpiration() {
        RememberMeToken.setClock(NOT_EXPIRATION_CLOCK);

        assertFalse(token.isExpired());
    }

    @Test
    @DisplayName("토큰이 만료 되었을시")
    void tokenIsExpiration() {
        RememberMeToken.setClock(EXPIRATION_CLOCK);

        assertTrue(token.isExpired());
    }


    @AfterEach
    void cleanUp() {
        RememberMeToken.setClock(DEFAULT_CLOCK);
    }
}
