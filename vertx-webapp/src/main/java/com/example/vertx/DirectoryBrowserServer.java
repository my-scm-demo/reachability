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
 * Directory Browser Server - BDSA-2025-14250 Demo
 *
 * An internal file-browsing portal that exposes directory listings for
 * shared team resources. Common use cases:
 *  - Build artifact browsers (CI/CD outputs)
 *  - Internal asset repositories
 *  - Shared media / file stores
 *  - Development tool asset servers
 *
 * VULNERABLE: Uses StaticHandler with directory listing enabled, triggering
 * StaticHandlerImpl.sendDirectoryListing() — BDSA-2025-14250.
 *
 * Pattern categories covered:
 *  - enabling_or_config_apis
 *  - dangerous_instantiations
 *  - other_relevant_patterns
 */
public class DirectoryBrowserServer extends AbstractVerticle {

    private static final Logger logger = LoggerFactory.getLogger(DirectoryBrowserServer.class);
    private static final int PORT = 7070;

    public static void main(String[] args) {
        Vertx vertx = Vertx.vertx();
        vertx.deployVerticle(new DirectoryBrowserServer());
    }

    @Override
    public void start(Promise<Void> startPromise) {
        Router router = Router.router(vertx);

        setupApiRoutes(router);
        setupDirectoryHandlers(router);

        vertx.createHttpServer()
            .requestHandler(router)
            .listen(PORT, result -> {
                if (result.succeeded()) {
                    startPromise.complete();
                    logger.info("Directory Browser started on port {}", PORT);
                    logger.info("  - Static:    http://localhost:{}/static/", PORT);
                    logger.info("  - Public:    http://localhost:{}/public/", PORT);
                    logger.info("  - Files:     http://localhost:{}/files/", PORT);
                    logger.info("  - Assets:    http://localhost:{}/assets/", PORT);
                    logger.warn("VULNERABLE to BDSA-2025-14250 (sendDirectoryListing)");
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
     * Configure static file handlers with directory listing.
     *
     * VULNERABLE PATTERNS — enabling_or_config_apis:
     *   router.route("/public/*").handler(StaticHandler.create("public"))
     *   router.route("/static/*").handler(StaticHandler.create().setDirectoryListing(true))
     *   router.route("/files/*").handler(StaticHandler.create("files").setDirectoryListing(true))
     *
     * VULNERABLE PATTERNS — dangerous_instantiations:
     *   StaticHandler.create("public")
     *   StaticHandler.create().setDirectoryListing(true)
     *   StaticHandler.create("files").setDirectoryListing(true)
     *
     * VULNERABLE PATTERNS — other_relevant_patterns:
     *   router.route("/public/*").handler(StaticHandler.create("public"))
     *   router.route("/static/*").handler(StaticHandler.create().setDirectoryListing(true))
     *   router.route("/files/*").handler(StaticHandler.create("files").setDirectoryListing(true))
     *   StaticHandler.create("public").setDirectoryListing(true).handle(routingContext)
     *   StaticHandler.create("files").handle(routingContext)
     */
    private void setupDirectoryHandlers(Router router) {

        // VULNERABLE PATTERN 1 (enabling): Public files with explicit webroot
        // Matches: router.route("/public/*").handler(StaticHandler.create("public"))
        router.route("/public/*").handler(StaticHandler.create("public"));

        // VULNERABLE PATTERN 2 (enabling): Static files with directory listing
        // Matches: router.route("/static/*").handler(StaticHandler.create().setDirectoryListing(true))
        router.route("/static/*").handler(StaticHandler.create().setDirectoryListing(true));

        // VULNERABLE PATTERN 3 (enabling): Named directory with listing enabled
        // Matches: router.route("/files/*").handler(StaticHandler.create("files").setDirectoryListing(true))
        router.route("/files/*").handler(StaticHandler.create("files").setDirectoryListing(true));

        // VULNERABLE PATTERNS (dangerous_instantiations): handler instances built separately
        // Matches: StaticHandler.create("public")
        StaticHandler handler1 = StaticHandler.create("public");
        // Matches: StaticHandler.create().setDirectoryListing(true)
        StaticHandler handler2 = StaticHandler.create().setDirectoryListing(true);
        // Matches: StaticHandler.create("files").setDirectoryListing(true)
        StaticHandler handler3 = StaticHandler.create("files").setDirectoryListing(true);

        // Register the pre-built handlers on additional mount points
        router.route("/shared/*").handler(handler1);
        router.route("/browse/*").handler(handler2);
        router.route("/downloads/*").handler(handler3);

        // VULNERABLE PATTERNS (other_relevant_patterns): explicit handle() invocations
        // Matches: StaticHandler.create("public").setDirectoryListing(true).handle(routingContext)
        router.route("/team/*").handler(routingContext -> {
            StaticHandler.create("public").setDirectoryListing(true).handle(routingContext);
        });

        // Matches: StaticHandler.create("files").handle(routingContext)
        router.route("/archive/*").handler(routingContext -> {
            StaticHandler.create("files").handle(routingContext);
        });

        logger.info("Directory browsing handlers configured (VULNERABLE to BDSA-2025-14250)");
    }

    @Override
    public void stop(Promise<Void> stopPromise) {
        logger.info("Shutting down directory browser");
        stopPromise.complete();
    }
}
