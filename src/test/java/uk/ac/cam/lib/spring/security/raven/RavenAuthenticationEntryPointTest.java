package uk.ac.cam.lib.spring.security.raven;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;
import uk.ac.cam.lib.spring.security.raven.hooks.DefaultRavenRequestCreator;

import javax.servlet.ServletException;
import java.io.IOException;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class RavenAuthenticationEntryPointTest {

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorRejectsNullRequestCreator() {
        new RavenAuthenticationEntryPoint(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorRejectsNullUrl() {
        new RavenAuthenticationEntryPoint(
            DefaultRavenRequestCreator.builder("").build(), null);
    }

    @Test
    public void testEntryPointAddsRedirectToRaven()
        throws IOException, ServletException {

        String url = "http://example.com/callback";

        RavenAuthenticationEntryPoint ep = new RavenAuthenticationEntryPoint(
            DefaultRavenRequestCreator.builder(url).build());

        assertThat(ep.getRavenAuthUri(),
            equalTo(RavenAuthenticationEntryPoint.DEFAULT_RAVEN_AUTH_URL));

        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse resp = new MockHttpServletResponse();

        // Run the entry point action
        ep.commence(req, resp, new InsufficientAuthenticationException("foo"));

        assertTrue(resp.containsHeader("Location"));
        assertTrue(resp.getHeader("Location").startsWith(
            RavenAuthenticationEntryPoint.DEFAULT_RAVEN_AUTH_URL.toString()));

        UriComponents uri = UriComponentsBuilder.fromUriString(
            resp.getHeader("Location")).build(false);

        assertThat(
            UriUtils.decode(uri.getQueryParams().getFirst("url"), "UTF-8"),
            equalTo(url));
    }
}
