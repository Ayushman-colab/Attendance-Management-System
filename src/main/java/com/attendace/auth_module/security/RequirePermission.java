package com.attendace.auth_module.security;


import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequirePermission {
    /**
     * Required permissions - user must have at least one of these
     */
    String[] value();

    /**
     * If true, user must have ALL specified permissions
     * If false (default), user needs ANY of the specified permissions
     */
    boolean requireAll() default false;
}
