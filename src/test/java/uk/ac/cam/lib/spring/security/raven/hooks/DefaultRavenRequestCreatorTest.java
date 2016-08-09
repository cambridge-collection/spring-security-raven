package uk.ac.cam.lib.spring.security.raven.hooks;

import com.google.common.collect.ImmutableMap;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.springframework.mock.web.MockHttpServletRequest;
import uk.ac.cam.lib.spring.security.raven.RavenRequestCreator;
import uk.ac.cam.lib.spring.security.raven.hooks.DefaultRavenRequestCreator.RequestParam;
import uk.ac.cam.ucs.webauth.WebauthRequest;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

public class DefaultRavenRequestCreatorTest {

    @Test
    public void testBuilderCreatesRequestCreatorWithUrl() {
        final String url = "http://example.com/";

        DefaultRavenRequestCreator c =
            DefaultRavenRequestCreator.builder(url).build();

        WebauthRequest r = c.createLoginRequest(new MockHttpServletRequest());
        assertThat(r.get("url"), equalTo(url));
    }

    @Test
    public void testBuilderCreatesRequestCreatorWithDefaultVersion() {
        DefaultRavenRequestCreator c =
            DefaultRavenRequestCreator.builder("").build();

        WebauthRequest r = c.createLoginRequest(new MockHttpServletRequest());
        assertThat(r.get("ver"), equalTo(
            "" + DefaultRavenRequestCreator.Builder.DEFAULT_VERSION));
    }

    @Test
    public void testBuilderCreatesRequestCreatorWithVersion() {
        DefaultRavenRequestCreator c =
            DefaultRavenRequestCreator.builder("", 2).build();

        WebauthRequest r = c.createLoginRequest(new MockHttpServletRequest());
        assertThat(r.get("ver"), equalTo("2"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testVersionMustBeInteger() {
        new DefaultRavenRequestCreator(
            ImmutableMap.of(RequestParam.url, "", RequestParam.ver, "foo"));
    }

    @RunWith(Parameterized.class)
    public static class RequiredParamsTest {

        private final Map<RequestParam, Object> values;

        public RequiredParamsTest(Map<RequestParam, Object> values) {
            this.values = values;
        }

        @Test(expected = IllegalArgumentException.class)
        public void testRequiredParamsMustBeProvided() {
            new DefaultRavenRequestCreator(this.values);
        }

        @Parameterized.Parameters
        public static Collection<Object[]> params() {
            return Arrays.asList(new Object[][]{
                {ImmutableMap.of()},
                {ImmutableMap.of(RequestParam.url, "")},
                {ImmutableMap.of(RequestParam.ver, 3)}
            });
        }
    }

    @RunWith(Parameterized.class)
    public static class CreatedParamsTest {

        @Parameterized.Parameters
        public static Collection<Object[]> params() {
            return Arrays.asList(new Object[][]{
                {
                    new TestParam(RequestParam.ver, 3, "3"),
                    new TestParam(RequestParam.url, "/foo", "/foo")
                },
                {
                    new TestParam(RequestParam.ver, 3, "3"),
                    new TestParam(RequestParam.url, "/foo"),
                    new TestParam(RequestParam.aauth, "pwd,x-foo"),
                    new TestParam(RequestParam.desc, "some desc"),
                    new TestParam(RequestParam.fail, "yes"),
                    new TestParam(RequestParam.iact, "yes"),
                    new TestParam(RequestParam.msg, "hello"),
                    new TestParam(RequestParam.params, "some-data")
                },
            }).stream()
                .map(params -> new Object[]{Arrays.asList(params)})
                .collect(Collectors.toList());
        }

        private final List<TestParam> testParams;

        public CreatedParamsTest(List<TestParam> testParams) {
            this.testParams = testParams;
        }

        private static class TestParam {
            public RequestParam param;
            public Object value;
            public String expected;

            public TestParam(RequestParam param, Object value) {
                this(param, value, (String)value);
            }

            public TestParam(RequestParam param, Object value, String expected) {
                this.param = param;
                this.value = value;
                this.expected = expected;
            }
        }

        private Map<RequestParam, Object> getParams() {
            return testParams.stream()
                .collect(Collectors.toMap(p -> p.param, p -> p.value));
        }

        private void assertContainsAllTestParams(WebauthRequest req) {
            // + 1 because a "date" field is added by default.
            assertThat(req.length(), equalTo(this.testParams.size() + 1));

            testParams.forEach(p ->
                assertThat(req.get(p.param.name()), equalTo(p.expected)));
        }

        @Test
        public void testParams() {
            RavenRequestCreator rrc =
                new DefaultRavenRequestCreator(getParams());

            assertContainsAllTestParams(
                rrc.createLoginRequest(new MockHttpServletRequest()));
        }
    }
}
