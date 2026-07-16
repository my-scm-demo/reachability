package com.example.vertx;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.StaticHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Static Resource Server - BDSA-2025-14251 Demo
 *
 * A production-style static asset server for a web application. Serves
 * frontend assets, stylesheets, scripts, and other static content while
 * explicitly excluding hidden files from the webroot.
 *
 * Common use cases:
 *  - SPA (Single Page App) asset serving
 *  - CDN-origin servers
 *  - Frontend build-output servers
 *  - Web application resource endpoints
 *
 * VULNERABLE: Uses StaticHandler with setIncludeHidden(false), which routes
 * all static file serving through StaticHandlerImpl.sendStatic() —
 * BDSA-2025-14251.
 *
 * Pattern categories covered:
 *  - enabling_or_config_apis
 *  - dangerous_instantiations
 *  - other_relevant_patterns
 */
public class StaticResourceServer extends AbstractVerticle {

    private static final Logger logger = LoggerFactory.getLogger(StaticResourceServer.class);
    private static final int PORT = 6060;

    public static void main(String[] args) {
        Vertx vertx = Vertx.vertx();
        vertx.deployVerticle(new StaticResourceServer());
    }

    @Override
    public void start(Promise<Void> startPromise) {
        Router router = Router.router(vertx);

        setupApiRoutes(router);
        setupStaticHandlers(router);

        vertx.createHttpServer()
            .requestHandler(router)
            .listen(PORT, result -> {
                if (result.succeeded()) {
                    startPromise.complete();
                    logger.info("Static Resource Server started on port {}", PORT);
                    logger.info("  - Static:  http://localhost:{}/static/", PORT);
                    logger.info("  - Assets:  http://localhost:{}/assets/", PORT);
                    logger.info("  - Public:  http://localhost:{}/public/", PORT);
                    logger.info("  - Files:   http://localhost:{}/files/", PORT);
                    logger.warn("VULNERABLE to BDSA-2025-14251 (sendStatic / setIncludeHidden)");
                } else {
                    startPromise.fail(result.cause());
                }
            });
    }

    private void setupApiRoutes(Router router) {
        router.get("/api/health").handler(ctx ->
            ctx.response()
                .putHeader("content-type", "application/json")
                .end(new JsonObject().put("status", "ok").encode()));
    }

    /**
     * Configure static handlers — all with hidden-file exclusion.
     *
     * VULNERABLE PATTERNS — enabling_or_config_apis:
     *   router.route("/static/*").handler(StaticHandler.create().setIncludeHidden(false))
     *   router.route("/assets/*").handler(StaticHandler.create("webroot").setIncludeHidden(false))
     *   router.route("/files/*").handler(StaticHandler.create().setIncludeHidden(false).setCachingEnabled(true))
     *
     * VULNERABLE PATTERNS — dangerous_instantiations:
     *   StaticHandler.create().setIncludeHidden(false)
     *   StaticHandler.create("webroot").setIncludeHidden(false)
     *   StaticHandler.create().setIncludeHidden(false).setCachingEnabled(true)
     *
     * VULNERABLE PATTERNS — other_relevant_patterns:
     *   router.route("/static/*").handler(StaticHandler.create().setIncludeHidden(false))
     *   router.route("/assets/*").handler(StaticHandler.create("webroot").setIncludeHidden(false))
     *   router.route("/files/*").handler(StaticHandler.create().setIncludeHidden(false).setCachingEnabled(true))
     *   StaticHandler.create().setIncludeHidden(false).handle(routingContext)
     *   StaticHandler.create("webroot").setIncludeHidden(false).handle(routingContext)
     */
    private void setupStaticHandlers(Router router) {

        // VULNERABLE PATTERN 1 (enabling): Static route — hidden files excluded
        // Matches: router.route("/static/*").handler(StaticHandler.create().setIncludeHidden(false))
        router.route("/static/*").handler(StaticHandler.create().setIncludeHidden(false));

        // VULNERABLE PATTERN 2 (enabling): Assets served from explicit webroot
        // Matches: router.route("/assets/*").handler(StaticHandler.create("webroot").setIncludeHidden(false))
        router.route("/assets/*").handler(StaticHandler.create("webroot").setIncludeHidden(false));

        // VULNERABLE PATTERN 3 (enabling): Files — hidden excluded and caching enabled
        // Matches: router.route("/files/*").handler(StaticHandler.create().setIncludeHidden(false).setCachingEnabled(true))
        router.route("/files/*").handler(StaticHandler.create().setIncludeHidden(false).setCachingEnabled(true));

        // VULNERABLE PATTERNS (dangerous_instantiations): pre-built handler instances
        // Matches: StaticHandler.create().setIncludeHidden(false)
        StaticHandler hiddenExcludedHandler = StaticHandler.create().setIncludeHidden(false);
        // Matches: StaticHandler.create("webroot").setIncludeHidden(false)
        StaticHandler webHandler = StaticHandler.create("webroot").setIncludeHidden(false);
        // Matches: StaticHandler.create().setIncludeHidden(false).setCachingEnabled(true)
        StaticHandler cachedHandler = StaticHandler.create().setIncludeHidden(false).setCachingEnabled(true);

        // Register the pre-built handlers on additional routes
        router.route("/app/*").handler(hiddenExcludedHandler);
        router.route("/dist/*").handler(webHandler);
        router.route("/theme/*").handler(cachedHandler);

        // VULNERABLE PATTERNS (other_relevant_patterns): explicit handle() invocations
        // Matches: StaticHandler.create().setIncludeHidden(false).handle(routingContext)
        router.route("/scripts/*").handler(routingContext -> {
            StaticHandler.create().setIncludeHidden(false).handle(routingContext);
        });

        // Matches: StaticHandler.create("webroot").setIncludeHidden(false).handle(routingContext)
        router.route("/public/*").handler(routingContext -> {
            StaticHandler.create("webroot").setIncludeHidden(false).handle(routingContext);
        });

        logger.info("Static resource handlers configured (VULNERABLE to BDSA-2025-14251)");
    }

    @Override
    public void stop(Promise<Void> stopPromise) {
        logger.info("Shutting down static resource server");
        stopPromise.complete();
    }
}
