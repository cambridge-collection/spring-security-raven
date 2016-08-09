package uk.ac.cam.lib.spring.security.raven.hooks;

import org.springframework.util.Assert;
import uk.ac.cam.lib.spring.security.raven.RavenRequestCreator;
import uk.ac.cam.ucs.webauth.WebauthRequest;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;


public class DefaultRavenRequestCreator implements RavenRequestCreator {

    private final Map<RequestParam, Object> values;

    public DefaultRavenRequestCreator(Map<RequestParam, Object> values) {
        Assert.notNull(values);

        this.values = Collections.unmodifiableMap(new EnumMap<>(values));
        validate();
    }

    private void validate() {
        if(!this.getValues().keySet().containsAll(RequestParam.REQUIRED)) {
            throw new IllegalArgumentException(
                "Not all required params were provided");
        }

        this.values.forEach((param, value) -> {
            try {
                param.validate(value);
            }
            catch(IllegalArgumentException e) {
                throw new IllegalArgumentException(String.format(
                    "Invalid value for key %s: %s - %s",
                    param, value, e.getMessage()), e);
            }
        });
    }

    public Map<RequestParam, Object> getValues() {
        return this.values;
    }

    @Override
    public WebauthRequest createLoginRequest(HttpServletRequest httpRequest) {
        WebauthRequest request = new WebauthRequest();

        this.getValues().forEach((param, value) ->
            request.set(param.name(), value.toString()));

        return request;
    }

    public static Builder builder(String returnUrl) {
        return builder(returnUrl,  3);
    }

    public static Builder builder(String returnUrl, int version) {
        return new Builder()
            .set(RequestParam.ver, version)
            .set(RequestParam.url, returnUrl);
    }

    public static class Builder {
        public static final int DEFAULT_VERSION = 3;

        private final Map<RequestParam, Object> values;

        public Builder() {
            this.values = new EnumMap<>(RequestParam.class);
        }

        public Builder set(RequestParam param, Object value) {
            Assert.notNull(param);
            Assert.notNull(value);

            this.values.put(param, value);
            return this;
        }

        public DefaultRavenRequestCreator build() {
            return new DefaultRavenRequestCreator(this.values);
        }
    }

    public enum RequestParam {
        ver(true, RequestParam::requireInt),
        url(true),
        desc,
        aauth,
        iact,
        msg,
        params,
        fail;

        private static void requireInt(Object value) {
            if(!(value instanceof Integer)) {
                throw new IllegalArgumentException(
                    "Expected an Integer, got: " + value);
            }
        }

        private static void requireString(Object value) {
            if(!(value instanceof String)) {
                throw new IllegalArgumentException(
                    "Expected a String, got: " + value);
            }
        }

        private final Optional<Consumer<Object>> validator;
        private final boolean isRequired;

        public static final Set<RequestParam> REQUIRED =
            Collections.unmodifiableSet(
            Arrays.stream(RequestParam.values())
                .filter(RequestParam::isRequired)
                .collect(Collectors.toCollection(
                    () -> EnumSet.noneOf(RequestParam.class))));


        RequestParam() {
            this(false);
        }

        RequestParam(boolean isRequired) {
            this(isRequired, RequestParam::requireString);
        }

        RequestParam(boolean isRequired, Consumer<Object> validator) {
            this.validator = Optional.ofNullable(validator);
            this.isRequired = isRequired;
        }

        public boolean isRequired() {
            return this.isRequired;
        }

        public void validate(Object value) {
            this.validator.ifPresent(validator -> validator.accept(value));
        }
    }
}
