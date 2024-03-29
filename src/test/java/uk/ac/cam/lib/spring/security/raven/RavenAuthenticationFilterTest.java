package uk.ac.cam.lib.spring.security.raven;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import uk.ac.cam.ucs.webauth.WebauthException;
import uk.ac.cam.ucs.webauth.WebauthRequest;
import uk.ac.cam.ucs.webauth.WebauthResponse;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;


public class RavenAuthenticationFilterTest {

    private static final String RESPONSE_PARAM = "WLS-Response";
    private static final String AUTH_RESPONSE =
        "1!200!!20160811T155817Z!1470931097-27163-123!http://" +
        "cudl-dev.lib.cam.ac.uk:80/auth/ravenlogin!hwtb2!!pwd!9793!!2!xxx";

    private static final Instant TEST_TIME =
        Instant.parse("2016-01-01T12:00:00.00Z");
    private static final Clock TEST_CLOCK =
        Clock.fixed(TEST_TIME, ZoneId.of("Z"));

    private RavenRequestCreator reqCreator;
    private WebauthRequest reqCreatorRequest;

    private HttpServletRequest preRavenRequest, postRavenRequest;

    private HttpServletResponse resp;

    private RequestCache requestCache;

    private static SavedRequest savedRequest(HttpServletRequest req) {
        return new DefaultSavedRequest(req, new PortResolverImpl());
    }

    @Before
    public void setUp() {
        resp = new MockHttpServletResponse();

        preRavenRequest = MockMvcRequestBuilders
            .request(HttpMethod.GET, "http://example.com/thing")
            .buildRequest(null);

        postRavenRequest = MockMvcRequestBuilders
            .request(HttpMethod.GET, "http://example.com/callback?{a}={b}",
                     RESPONSE_PARAM, AUTH_RESPONSE)
            .buildRequest(null);

        SavedRequest savedPreRavenRequest = savedRequest(preRavenRequest);

        reqCreatorRequest = new WebauthRequest();
        reqCreatorRequest.set("url", "http://example.com/foo");

        reqCreator = mock(RavenRequestCreator.class);
        when(reqCreator.createLoginRequest(preRavenRequest))
            .thenReturn(reqCreatorRequest);

        requestCache = mock(RequestCache.class);
        when(requestCache.getRequest(postRavenRequest, resp))
            .thenReturn(savedPreRavenRequest);

        doReturn(reqCreatorRequest)
            .when(reqCreator).createLoginRequest(anyObject());
    }

    @Test
    public void testAuthResponseIsCorrectlyStructured() throws WebauthException {
        new WebauthResponse(AUTH_RESPONSE);
    }

    @Test(expected=AuthenticationException.class)
    public void testAttemptAuthenticationThrowsWithoutAuthQueryParam() throws IOException, ServletException {
        RavenAuthenticationFilter filter =
            new RavenAuthenticationFilter(
                mock(AuthenticationManager.class), reqCreator,
                new NullRequestCache());

        HttpServletRequest badAuthRequest = MockMvcRequestBuilders.request(
            HttpMethod.GET, "http://example.com/callback?no-param-here")
            .buildRequest(null);

        filter.attemptAuthentication(badAuthRequest, resp);
    }

    @Test
    public void testFilterPassesUnauthenticatedRavenTokenToAuthManager()
        throws IOException, ServletException, WebauthException {

        AuthenticationManager authManager = mock(AuthenticationManager.class);
        RavenAuthenticationToken result = mock(RavenAuthenticationToken.class);

        doReturn(result).when(authManager).authenticate(anyObject());

        RavenAuthenticationFilter filter =
            new RavenAuthenticationFilter(
                authManager, reqCreator, requestCache,
                AnyRequestMatcher.INSTANCE, TEST_CLOCK, RESPONSE_PARAM);

        Authentication actualResult =
            filter.attemptAuthentication(postRavenRequest, resp);

        assertThat(actualResult, is(result));

        verify(requestCache).getRequest(postRavenRequest, resp);
        verify(reqCreator).createLoginRequest(anyObject());

        // Verify the token passed to the AuthenticationManager
        ArgumentCaptor<Authentication> authCaptor = ArgumentCaptor.forClass(Authentication.class);
        verify(authManager, times(1)).authenticate(authCaptor.capture());

        RavenAuthenticationToken token =
            (RavenAuthenticationToken)authCaptor.getValue();

        assertThat(token.getRavenRequest().get(),
                   is(equalTo(reqCreatorRequest)));
        assertThat(token.getRavenResponse().get().getToken(),
                   is(equalTo(AUTH_RESPONSE)));
        assertThat(token.getResponseReceivedTime().get(),
                   is(equalTo(TEST_TIME)));
    }

    private static <T> Matcher<T> satisfiesPredicate(Predicate<T> predicate) {
        return satisfiesPredicate(
            predicate,
            desc -> desc.appendText("should satisfy predicate: ")
                        .appendValue(predicate));
    }

    private static <T> Matcher<T> satisfiesPredicate(
        Predicate<T> predicate, Consumer<Description> describer) {

        return new TypeSafeMatcher<T>() {
            @Override
            protected boolean matchesSafely(T item) {
                return predicate.test(item);
            }

            @Override
            public void describeTo(Description description) {
                describer.accept(description);
            }
        };
    }

    @RunWith(Parameterized.class)
    public static class FilterRequestMatchingTest {
        @Parameters
        public static Iterable<Object[]> params() {
            return Arrays.asList(new Object[][]{
                {"foo", "https://example.com/blah/blah?foo=abcd&xyz",
                    "GET", true},
                {"foo", "https://example.com/blah/blah?foo=abcd&xyz",
                    "POST", true},
                {"WLS-Response", "https://example.com/blah/blah?" +
                    "x=y&WLS-Response=abcd&xyz", "GET", true},
                {"WLS-Response", "https://example.com/blah/blah",
                    "GET", false}
            }).stream()
                .map(x -> { x[1] = URI.create((String)x[1]); return x; })
                .collect(Collectors.toList());
        }

        @Parameter(0)
        public String paramName;

        @Parameter(1)
        public URI requestUri;

        @Parameter(2)
        public String requestMethod;

        @Parameter(3)
        public boolean shouldMatch;

        @Test public void testFilter() {
            RequestMatcher matcher = RavenAuthenticationFilter
                .queryContainsResponseParamRequestMatcher(this.paramName);

            HttpServletRequest req = MockMvcRequestBuilders
                .request(this.requestMethod, this.requestUri)
                .buildRequest(null);

            assertThat(matcher.matches(req), is(equalTo(this.shouldMatch)));
        }
    }
}
