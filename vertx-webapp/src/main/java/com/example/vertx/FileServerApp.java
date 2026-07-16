package com.example.vertx;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.StaticHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Internal File Browser Application
 *
 * A realistic internal web application for browsing and accessing company files.
 * Common use case: Internal file server for development teams, documentation,
 * build artifacts, and shared resources.
 *
 * VULNERABLE: Uses StaticHandler.create() patterns that are susceptible to
 * CVE-2023-24815 (BDSA-2023-2163) path traversal on Windows systems.
 *
 * This represents a typical pattern seen in:
 * - CI/CD artifact servers
 * - Internal documentation sites
 * - Development file sharing tools
 * - Build output browsers
 */
public class FileServerApp extends AbstractVerticle {

    private static final Logger logger = LoggerFactory.getLogger(FileServerApp.class);
    private static final int PORT = 8888;

    public static void main(String[] args) {
        Vertx vertx = Vertx.vertx();
        vertx.deployVerticle(new FileServerApp());
    }

    @Override
    public void start(Promise<Void> startPromise) {
        HttpServer server = vertx.createHttpServer();
        Router router = Router.router(vertx);

        // Setup routes
        setupApiRoutes(router);
        setupStaticRoutes(router);

        // Start the server
        server.requestHandler(router).listen(PORT, http -> {
            if (http.succeeded()) {
                startPromise.complete();
                logger.info("Internal File Browser started on port {}", PORT);
                logger.info("  - Browse files: http://localhost:{}/", PORT);
                logger.info("  - API docs: http://localhost:{}/api/info", PORT);
                logger.warn("⚠ VULNERABLE: CVE-2023-24815 (Path Traversal via StaticHandler)");
            } else {
                startPromise.fail(http.cause());
                logger.error("Failed to start server", http.cause());
            }
        });
    }

    /**
     * Setup API routes for file operations
     */
    private void setupApiRoutes(Router router) {
        // API info endpoint
        router.get("/api/info").handler(ctx -> {
            JsonObject info = new JsonObject()
                .put("name", "Internal File Browser")
                .put("version", "1.0.0")
                .put("endpoints", new JsonArray()
                    .add("/api/health - Health check")
                    .add("/api/files - List available files")
                    .add("/builds/* - Build artifacts")
                    .add("/docs/* - Documentation")
                    .add("/reports/* - Test reports"));

            ctx.response()
                .putHeader("content-type", "application/json")
                .end(info.encodePrettily());
        });

        // Health check
        router.get("/api/health").handler(ctx -> {
            ctx.response()
                .putHeader("content-type", "application/json")
                .end(new JsonObject().put("status", "ok").encode());
        });

        // List files API
        router.get("/api/files").handler(ctx -> {
            ctx.response()
                .putHeader("content-type", "application/json")
                .end(new JsonObject()
                    .put("directories", new JsonArray()
                        .add("builds")
                        .add("docs")
                        .add("reports"))
                    .encode());
        });
    }

    /**
     * Setup static file handlers - VULNERABLE PATTERNS
     *
     * These are typical real-world patterns that developers use when
     * serving static files with Vert.x, but they're vulnerable to
     * CVE-2023-24815 path traversal attacks.
     *
     * Signature: io.vertx.ext.web.handler.StaticHandler.create()
     */
    private void setupStaticRoutes(Router router) {
        // VULNERABLE: Serve build artifacts
        // Real use case: CI/CD system serving build outputs
        router.route("/builds/*").handler(StaticHandler.create("builds"));

        // VULNERABLE: Serve documentation
        // Real use case: Internal API docs, wikis, generated documentation
        router.route("/docs/*").handler(StaticHandler.create("docs"));

        // VULNERABLE: Serve test reports
        // Real use case: Test coverage reports, test results
        router.route("/reports/*").handler(StaticHandler.create("reports"));

        // VULNERABLE: Catch-all for main file browser
        // Real use case: Default file serving for the root path
        // This is the most dangerous pattern - wildcard route
        router.route("/*").handler(StaticHandler.create());

        logger.info("Static handlers configured for: /builds, /docs, /reports, /");
    }

    @Override
    public void stop(Promise<Void> stopPromise) {
        logger.info("Shutting down file browser");
        stopPromise.complete();
    }
}
