package no.nav.fo.veilarbsituasjon.utils;

import lombok.SneakyThrows;

import java.lang.reflect.Method;

public class ReflectionUtils {

    @SneakyThrows
    public static Method getMethod(Class<?> proxyClass, String methodName, Class<?>... args) {
        return proxyClass.getMethod(methodName,args);
    }

}
