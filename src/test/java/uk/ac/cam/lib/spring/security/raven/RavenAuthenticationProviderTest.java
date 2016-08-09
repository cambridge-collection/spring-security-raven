package uk.ac.cam.lib.spring.security.raven;


import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import uk.ac.cam.ucs.webauth.WebauthException;
import uk.ac.cam.ucs.webauth.WebauthRequest;
import uk.ac.cam.ucs.webauth.WebauthResponse;
import uk.ac.cam.ucs.webauth.WebauthValidator;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class RavenAuthenticationProviderTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Before
    public void setUp() {

    }

    @Test
    public void testProviderSupportsRavenAuthToken() {
        RavenAuthenticationProvider provider = new RavenAuthenticationProvider(
            mock(WebauthValidator.class),
            mock(AuthenticatedRavenTokenCreator.class));

        assertThat(provider.supports(RavenAuthenticationToken.class), is(true));
    }

    @Test
    public void testGetters() {
        WebauthValidator validator = mock(WebauthValidator.class);
        AuthenticatedRavenTokenCreator creator =
            mock(AuthenticatedRavenTokenCreator.class);

        RavenAuthenticationProvider provider =
            new RavenAuthenticationProvider(validator, creator);

        assertThat(provider.getWebauthValidator(), is(sameInstance(validator)));
        assertThat(provider.getTokenCreator(), is(sameInstance(creator)));
    }

    @Test
    public void testAuthenticateThrowsRavenAuthExceptionIfAuthResponseInvalid()
        throws WebauthException {

        WebauthValidator validator = mock(WebauthValidator.class);
        AuthenticatedRavenTokenCreator creator = mock(
            AuthenticatedRavenTokenCreator.class);
        RavenAuthenticationToken token = mock(RavenAuthenticationToken.class);

        WebauthRequest req = mock(WebauthRequest.class);
        WebauthResponse resp = mock(WebauthResponse.class);

        when(token.getRavenRequest())
            .thenReturn(Optional.of(req));
        when(token.getRavenResponse())
            .thenReturn(Optional.of(resp));
        when(token.getResponseReceivedTime())
            .thenReturn(Optional.of(Instant.ofEpochMilli(123456)));

        RavenAuthenticationProvider provider =
            new RavenAuthenticationProvider(validator, creator);

        doThrow(WebauthException.class)
            .when(validator).validate(req, resp, 123456);

        thrown.expect(RavenAuthenticationException.class);
        try {
            provider.authenticate(token);
        }
        catch(RavenAuthenticationException e) {
            verify(validator).validate(req, resp, 123456);
            verify(token, atLeastOnce()).getRavenRequest();
            verify(token, atLeastOnce()).getRavenResponse();
            verify(token, atLeastOnce()).getResponseReceivedTime();
            verifyNoMoreInteractions(validator, token, creator);

            throw e;
        }
    }

    @Test
    public void testTokenCreatorMustCreateAuthenticatedToken() {
        WebauthValidator validator = mock(WebauthValidator.class);
        AuthenticatedRavenTokenCreator creator = mock(
            AuthenticatedRavenTokenCreator.class);

        RavenAuthenticationToken token = mock(RavenAuthenticationToken.class);
        when(token.getRavenRequest())
            .thenReturn(Optional.of(mock(WebauthRequest.class)));
        when(token.getRavenResponse())
            .thenReturn(Optional.of(mock(WebauthResponse.class)));
        when(token.getResponseReceivedTime())
            .thenReturn(Optional.of(Instant.ofEpochMilli(123456)));

        RavenAuthenticationToken authenticatedToken =
            mock(RavenAuthenticationToken.class);
        when(authenticatedToken.isAuthenticated()).thenReturn(false);

        when(creator.createAuthenticatedToken(token))
            .thenReturn(authenticatedToken);

        RavenAuthenticationProvider provider =
            new RavenAuthenticationProvider(validator, creator);

        thrown.expect(IllegalStateException.class);
        thrown.expectMessage("unauthenticated");
        provider.authenticate(token);
    }

    @Test
    public void testAuthenticateReturnsAuthenticatedToken() {
        WebauthValidator validator = mock(WebauthValidator.class);
        AuthenticatedRavenTokenCreator creator = mock(
            AuthenticatedRavenTokenCreator.class);

        RavenAuthenticationToken token = mock(RavenAuthenticationToken.class);
        when(token.getRavenRequest())
            .thenReturn(Optional.of(mock(WebauthRequest.class)));
        when(token.getRavenResponse())
            .thenReturn(Optional.of(mock(WebauthResponse.class)));
        when(token.getResponseReceivedTime())
            .thenReturn(Optional.of(Instant.ofEpochMilli(123456)));

        RavenAuthenticationToken authenticatedToken =
            mock(RavenAuthenticationToken.class);
        when(authenticatedToken.isAuthenticated()).thenReturn(true);

        when(creator.createAuthenticatedToken(token))
            .thenReturn(authenticatedToken);

        RavenAuthenticationProvider provider =
            new RavenAuthenticationProvider(validator, creator);

        assertThat(provider.authenticate(token),
                   is(sameInstance(authenticatedToken)));
    }

    @RunWith(Parameterized.class)
    public static class MissingCredentialsTest {
        @Parameters
        public static Iterable<Object[]> params() {
            return Arrays.asList(new Boolean[][]{
                {true, true, false},
                {true, false, true},
                {false, true, true},

                {false, false, true},
                {false, true, false},
                {true, false, false}
            });
        }

        @Rule
        public ExpectedException thrown = ExpectedException.none();

        private Optional<WebauthRequest> req;
        private Optional<WebauthResponse> resp;
        private Optional<Instant> ts;

        public MissingCredentialsTest(boolean req, boolean resp, boolean ts) {
            this.req = req ? Optional.of(mock(WebauthRequest.class))
                           : Optional.empty();

            this.resp = resp ? Optional.of(mock(WebauthResponse.class))
                             : Optional.empty();

            this.ts = ts ? Optional.of(Instant.ofEpochMilli(456789123))
                         : Optional.empty();
        }

        @Test
        public void testThrowsIfCredentialsMissing() {
            RavenAuthenticationProvider provider =
                new RavenAuthenticationProvider(
                    mock(WebauthValidator.class),
                    mock(AuthenticatedRavenTokenCreator.class));

            RavenAuthenticationToken token = mock(RavenAuthenticationToken.class);

            when(token.getRavenRequest()).thenReturn(req);
            when(token.getRavenResponse()).thenReturn(resp);
            when(token.getResponseReceivedTime()).thenReturn(ts);

            thrown.expect(RavenAuthenticationException.class);
            thrown.expectMessage(
                "Credentials have been erased before authentication");

            provider.authenticate(token);
        }
    }
}
