package uk.ac.cam.lib.spring.security.raven;


import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import uk.ac.cam.ucs.webauth.WebauthException;
import uk.ac.cam.ucs.webauth.WebauthRequest;
import uk.ac.cam.ucs.webauth.WebauthResponse;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.empty;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class RavenAuthenticationTokenTest {

    private static final String EXAMPLE_RESPONSE =
        "1!200!!20160811T155817Z!1470931097-27163-123!http://" +
        "cudl-dev.lib.cam.ac.uk:80/auth/ravenlogin!hwtb2!!pwd!9793!!2!xxx";

    private RavenAuthenticationToken createUnauthenticatedToken()
        throws WebauthException {

        WebauthResponse resp = new WebauthResponse(EXAMPLE_RESPONSE);

        return new RavenAuthenticationToken(
            new WebauthRequest(), resp, Instant.now());
    }

    @Test
    public void testUnauthenticatedPrincipalIsCrsid() throws WebauthException {
        assertThat(createUnauthenticatedToken().getPrincipal(),
                   equalTo("hwtb2"));
    }

    @Test
    public void testUnuathenticatedAuthoritiesListIsEmpty()
        throws WebauthException {

        assertThat(createUnauthenticatedToken().getAuthorities(), is(empty()));
    }


    @Test
    public void testUnauthenticatedTokenIsNotAuthenticated()
        throws WebauthException {

        assertFalse(createUnauthenticatedToken().isAuthenticated());
    }

    @Test
    public void testUnauthenticatedCtorArgsArePresent()
        throws WebauthException {

        WebauthResponse resp = new WebauthResponse(EXAMPLE_RESPONSE);
        WebauthRequest req = new WebauthRequest();
        Instant i = Instant.now();

        RavenAuthenticationToken t = new RavenAuthenticationToken(req, resp, i);

        assertTrue(t.hasCredentials());
        assertThat(t.getCredentials().get(),
            equalTo(t.getRavenResponse().get()));

        assertThat(t.getRavenResponse().get(), equalTo(resp));
        assertThat(t.getRavenRequest().get(), equalTo(req));
        assertThat(t.getResponseReceivedTime().get(), equalTo(i));
    }

    @Test
    public void testEraseCredentials() throws WebauthException {
        RavenAuthenticationToken t = createUnauthenticatedToken();
        assertTrue(t.hasCredentials());
        assertTrue(t.getRavenRequest().isPresent());
        assertTrue(t.getRavenResponse().isPresent());
        assertTrue(t.getResponseReceivedTime().isPresent());

        t.eraseCredentials();
        assertFalse(t.hasCredentials());
        assertFalse(t.getRavenRequest().isPresent());
        assertFalse(t.getRavenResponse().isPresent());
        assertFalse(t.getResponseReceivedTime().isPresent());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUnauthenticatedAuthStatusCannotBeModified()
        throws WebauthException {

        createUnauthenticatedToken().setAuthenticated(true);
    }

    @Test
    public void testAuthenticatedTokenIsAuthenticated()
        throws WebauthException {

        assertTrue(createUnauthenticatedToken()
            .authenticate("foo", null)
            .isAuthenticated());
    }

    @Test
    public void testAuthenticateReturnsNewToken() throws WebauthException {
        RavenAuthenticationToken unauthenticated = createUnauthenticatedToken();
        RavenAuthenticationToken authenticated =
            unauthenticated.authenticate("", null);

        assertNotSame(unauthenticated, authenticated);
        assertTrue(authenticated.isAuthenticated());
        assertFalse(unauthenticated.isAuthenticated());
    }

    @Test
    public void testAuthenticateReplacesPrincipal() throws WebauthException {
        Object newPrincipal = new Object();
        RavenAuthenticationToken authenticated =
            createUnauthenticatedToken().authenticate(newPrincipal, null);

        assertSame(authenticated.getPrincipal(), newPrincipal);
    }

    @Test
    public void testAuthenticateSetsAuthorities() throws WebauthException {
        List<GrantedAuthority> grants = Arrays.asList(
            new SimpleGrantedAuthority("foo"),
            new SimpleGrantedAuthority("bar"),
            new SimpleGrantedAuthority("baz")
        );
        RavenAuthenticationToken authenticated =
            createUnauthenticatedToken().authenticate("", grants);

        assertEquals(authenticated.getAuthorities(), grants);
    }
}
