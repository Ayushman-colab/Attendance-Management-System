package com.attendace.auth_module.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.AntPathMatcher;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

@Configuration
public class SwaggerConfig {

    private static final String API_TITLE = "Gym Management - Auth Service API";
    private static final String API_VERSION = "1.0";
    private static final String SECURITY_SCHEME_NAME = "bearerAuth";
    private static final String API_PATH = "/api/**";

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title(API_TITLE)
                        .version(API_VERSION)
                        .description("API documentation for Gym Management System - Authentication Service. \n\n" +
                                "### How to use:\n" +
                                "1. First, authenticate using the `/api/auth/login` endpoint\n" +
                                "2. Copy the received JWT token\n" +
                                "3. Click the 'Authorize' button and enter: `Bearer <your_token>`")
                        .contact(new Contact()
                                .name("Gym Management Support")
                                .email("support@gymmanagement.com"))
                        .license(new License()
                                .name("Apache 2.0")
                                .url("https://www.apache.org/licenses/LICENSE-2.0.html")))
                .components(new Components()
                        .addSecuritySchemes(SECURITY_SCHEME_NAME,
                                new SecurityScheme()
                                        .name(SECURITY_SCHEME_NAME)
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("JWT token obtained after successful authentication")));
    }

    @Bean
    public GroupedOpenApi publicApi() {
        return GroupedOpenApi.builder()
                .group("auth-service")
                .pathsToMatch(API_PATH)
                .addOpenApiCustomizer(secureOperationsCustomiser())
                .build();
    }

    @Bean
    public OpenApiCustomizer secureOperationsCustomiser() {
        final List<String> publicEndpoints = Arrays.stream(SecurityConfig.publicEndpoint).toList();

        final AntPathMatcher pathMatcher = new AntPathMatcher();

        return openApi -> {
            if (openApi.getPaths() == null) return;

            openApi.getPaths().forEach((path, pathItem) -> {
                pathItem.readOperations().forEach(operation -> {
                    boolean isPublic = publicEndpoints.stream()
                            .anyMatch(pattern -> Objects.equals(pattern, path) || pathMatcher.match(pattern, path));

                    if (isPublic) {
                        operation.setSecurity(List.of());
                    } else {
                        operation.addSecurityItem(new SecurityRequirement().addList(SECURITY_SCHEME_NAME));
                    }
                });
            });
        };
    }
}
