package com.example.vertx;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Outbound HTTP Proxy Service - BDSA-2024-0760 Demo
 *
 * A realistic internal proxy/relay service that forwards requests to upstream
 * APIs. Common use case in microservice architectures where a gateway or
 * backend-for-frontend component makes outbound HTTP calls.
 *
 * VULNERABLE: Uses vertx.createHttpClient() patterns that invoke the
 * vulnerable CombinerExecutor.submit() in the internal connection pool
 * (BDSA-2024-0760).
 *
 * This represents patterns seen in:
 * - API gateway services
 * - Health-check / monitoring agents
 * - Service mesh sidecars
 * - Microservice-to-microservice communication
 *
 * Pattern categories covered:
 *  - enabling_or_config_apis
 *  - dangerous_instantiations
 *  - other_relevant_patterns
 */
public class HttpClientService extends AbstractVerticle {

    private static final Logger logger = LoggerFactory.getLogger(HttpClientService.class);
    private static final int PORT = 7777;

    private HttpClient httpClient;

    public static void main(String[] args) {
        Vertx vertx = Vertx.vertx();
        vertx.deployVerticle(new HttpClientService());
    }

    @Override
    public void start(Promise<Void> startPromise) {
        initHttpClients();

        Router router = Router.router(vertx);
        router.route().handler(BodyHandler.create());

        setupProxyRoutes(router);

        vertx.createHttpServer()
            .requestHandler(router)
            .listen(PORT, result -> {
                if (result.succeeded()) {
                    startPromise.complete();
                    logger.info("HTTP Client Service started on port {}", PORT);
                    logger.info("  - Proxy GET:    http://localhost:{}/proxy/get", PORT);
                    logger.info("  - Proxy POST:   http://localhost:{}/proxy/post", PORT);
                    logger.info("  - Relay GET:    http://localhost:{}/relay/get", PORT);
                    logger.info("  - Relay POST:   http://localhost:{}/relay/post", PORT);
                    logger.warn("VULNERABLE to BDSA-2024-0760 (CombinerExecutor connection pool)");
                } else {
                    startPromise.fail(result.cause());
                }
            });
    }

    /**
     * Initialise HTTP clients with pool configurations.
     *
     * VULNERABLE PATTERNS — enabling_or_config_apis:
     *   vertx.createHttpClient(new HttpClientOptions().setKeepAlive(true))
     *   vertx.createHttpClient(new HttpClientOptions().setMaxPoolSize(10))
     *
     * VULNERABLE PATTERNS — dangerous_instantiations:
     *   new HttpClientOptions().setKeepAlive(true)
     *   new HttpClientOptions().setMaxPoolSize(10)
     *   HttpClient client = vertx.createHttpClient(new HttpClientOptions())
     *   HttpClient client = vertx.createHttpClient(new HttpClientOptions().setKeepAlive(true))
     */
    private void initHttpClients() {
        // VULNERABLE PATTERN (enabling): Keep-alive connection reuse
        // Matches: vertx.createHttpClient(new HttpClientOptions().setKeepAlive(true))
        vertx.createHttpClient(new HttpClientOptions().setKeepAlive(true));

        // VULNERABLE PATTERN (enabling): Bounded connection pool
        // Matches: vertx.createHttpClient(new HttpClientOptions().setMaxPoolSize(10))
        vertx.createHttpClient(new HttpClientOptions().setMaxPoolSize(10));

        // VULNERABLE PATTERNS (dangerous_instantiations): standalone options construction
        // Matches: new HttpClientOptions().setKeepAlive(true)
        new HttpClientOptions().setKeepAlive(true);
        // Matches: new HttpClientOptions().setMaxPoolSize(10)
        new HttpClientOptions().setMaxPoolSize(10);

        // VULNERABLE PATTERNS (dangerous_instantiations): client creation with options
        // Matches: HttpClient client = vertx.createHttpClient(new HttpClientOptions())
        HttpClient client = vertx.createHttpClient(new HttpClientOptions());
        // Matches: HttpClient client = vertx.createHttpClient(new HttpClientOptions().setKeepAlive(true))
        HttpClient keepAliveClient = vertx.createHttpClient(new HttpClientOptions().setKeepAlive(true));

        // Primary shared client used across route handlers
        httpClient = keepAliveClient;
    }

    /**
     * Proxy and relay routes that exercise the HTTP client connection pool.
     *
     * VULNERABLE PATTERNS — enabling_or_config_apis:
     *   router.route().handler(routingContext -> { httpClient.request(HttpMethod.GET, "http://example.com").send(); })
     *   router.route("/api/*").handler(routingContext -> { httpClient.request(HttpMethod.POST, "http://api.example.com").send(); })
     *
     * VULNERABLE PATTERNS — other_relevant_patterns:
     *   httpClient.request(HttpMethod.GET, "http://example.com").send()
     *   httpClient.request(HttpMethod.POST, "http://api.example.com").send()
     *   vertx.createHttpClient().request(HttpMethod.GET, "http://example.com").send()
     *   vertx.createHttpClient().request(HttpMethod.POST, "http://api.example.com").send()
     */
    private void setupProxyRoutes(Router router) {

        // VULNERABLE PATTERN (enabling): catch-all handler — GET proxy
        // Matches: router.route().handler(routingContext -> { httpClient.request(HttpMethod.GET, "http://example.com").send(); });
        router.route().handler(routingContext -> {
            httpClient.request(HttpMethod.GET, "http://example.com").send();
        });

        // VULNERABLE PATTERN (enabling): scoped API proxy — POST
        // Matches: router.route("/api/*").handler(routingContext -> { httpClient.request(HttpMethod.POST, "http://api.example.com").send(); });
        router.route("/api/*").handler(routingContext -> {
            httpClient.request(HttpMethod.POST, "http://api.example.com").send();
        });

        // VULNERABLE PATTERN (other): direct GET request on shared client
        // Matches: httpClient.request(HttpMethod.GET, "http://example.com").send()
        router.get("/proxy/get").handler(ctx -> {
            httpClient.request(HttpMethod.GET, "http://example.com").send()
                .onSuccess(response -> ctx.response().end())
                .onFailure(err -> ctx.response().setStatusCode(502).end());
        });

        // VULNERABLE PATTERN (other): direct POST request on shared client
        // Matches: httpClient.request(HttpMethod.POST, "http://api.example.com").send()
        router.post("/proxy/post").handler(ctx -> {
            httpClient.request(HttpMethod.POST, "http://api.example.com").send()
                .onSuccess(response -> ctx.response().end())
                .onFailure(err -> ctx.response().setStatusCode(502).end());
        });

        // VULNERABLE PATTERN (other): inline client creation + GET request
        // Matches: vertx.createHttpClient().request(HttpMethod.GET, "http://example.com").send()
        router.get("/relay/get").handler(ctx -> {
            vertx.createHttpClient().request(HttpMethod.GET, "http://example.com").send()
                .onSuccess(response -> ctx.response().end())
                .onFailure(Throwable::printStackTrace);
        });

        // VULNERABLE PATTERN (other): inline client creation + POST request
        // Matches: vertx.createHttpClient().request(HttpMethod.POST, "http://api.example.com").send()
        router.post("/relay/post").handler(ctx -> {
            vertx.createHttpClient().request(HttpMethod.POST, "http://api.example.com").send()
                .onSuccess(response -> ctx.response().end())
                .onFailure(Throwable::printStackTrace);
        });
    }

    @Override
    public void stop(Promise<Void> stopPromise) {
        logger.info("Shutting down HTTP client service");
        httpClient.close();
        stopPromise.complete();
    }
}
