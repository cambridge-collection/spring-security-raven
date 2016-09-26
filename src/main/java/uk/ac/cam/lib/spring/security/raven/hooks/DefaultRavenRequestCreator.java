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

import static uk.ac.cam.lib.spring.security.raven.hooks.DefaultRavenRequestCreator.Builder.DEFAULT_VERSION;


public class DefaultRavenRequestCreator implements RavenRequestCreator {

    @FunctionalInterface
    public interface PerRequestParamProducer {
        Object getRequestValue(RequestParam param, HttpServletRequest request);
    }

    private final Map<RequestParam, PerRequestParamProducer> valueProducers;

    public static DefaultRavenRequestCreator fromFixedValues(Map<RequestParam, Object> values) {
        Assert.notNull(values);

        return fromPerRequestValues(values.entrySet().stream().collect(
            Collectors.toMap(
                e -> e.getKey(),
                e -> staticProducer(e.getValue())
            )
        ));
    }

    public static DefaultRavenRequestCreator fromPerRequestValues(
        Map<RequestParam, PerRequestParamProducer> valueProducers) {

        return new DefaultRavenRequestCreator(valueProducers);
    }

    private DefaultRavenRequestCreator(
        Map<RequestParam, PerRequestParamProducer> valueProducers) {

        Assert.notNull(valueProducers);

        this.valueProducers = Collections.unmodifiableMap(
            new EnumMap<>(valueProducers));
        validate();
    }

    private static PerRequestParamProducer staticProducer(Object value) {
        return (p, r) -> value;
    }

    private void validate() {
        if(!this.valueProducers.keySet().containsAll(RequestParam.REQUIRED)) {
            throw new IllegalArgumentException(
                "Not all required params were provided");
        }
    }

    @Override
    public WebauthRequest createLoginRequest(HttpServletRequest httpRequest) {
        WebauthRequest request = new WebauthRequest();

        this.valueProducers.forEach((param, valueProducer) -> {
            Object value = valueProducer.getRequestValue(param, httpRequest);

            try {
                param.validate(value);
            }
            catch(IllegalArgumentException e) {
                throw new RuntimeException(String.format(
                    "PerRequestParamProducer produced invalid value for key " +
                    "%s: %s - %s", param, value, e.getMessage()), e);
            }

            request.set(param.name(), value.toString());
        });


        return request;
    }

    public static Builder builder(PerRequestParamProducer returnUrl) {
        return builder(returnUrl, DEFAULT_VERSION);
    }

    public static Builder builder(PerRequestParamProducer returnUrl,
                                  int version) {
        return new Builder()
            .withValue(RequestParam.ver, version)
            .withDynamicValue(RequestParam.url, returnUrl);
    }

    public static Builder builder(String returnUrl) {
        return builder(returnUrl,  DEFAULT_VERSION);
    }

    public static Builder builder(String returnUrl, int version) {
        return new Builder()
            .withValue(RequestParam.ver, version)
            .withValue(RequestParam.url, returnUrl);
    }

    public static class Builder {
        public static final int DEFAULT_VERSION = 3;

        private final Map<RequestParam, PerRequestParamProducer> valueProducers;

        public Builder() {
            this.valueProducers = new EnumMap<>(RequestParam.class);
        }

        public Builder withValue(RequestParam param, String value) {
            return _withValue(param, value);
        }

        public Builder withValue(RequestParam param, int value) {
            return _withValue(param, value);
        }

        private Builder _withValue(RequestParam param, Object value) {
            Assert.notNull(param);
            Assert.notNull(value);
            param.validate(value);

            return this.withDynamicValue(param, staticProducer(value));
        }

        public Builder withDynamicValue(
            RequestParam param, PerRequestParamProducer producer) {

            Assert.notNull(param);
            Assert.notNull(producer);

            this.valueProducers.put(param, producer);
            return this;
        }

        public DefaultRavenRequestCreator build() {
            return new DefaultRavenRequestCreator(this.valueProducers);
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
