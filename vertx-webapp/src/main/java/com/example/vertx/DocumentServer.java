package com.example.vertx;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.StaticHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Document Management System - A realistic enterprise application
 *
 * This application demonstrates real-world usage of Vert.x StaticHandler
 * that is vulnerable to CVE-2023-24815 (BDSA-2023-2163).
 *
 * Use Case: Internal document management system where employees can:
 * - Upload company documents
 * - Browse shared files
 * - Access training materials
 * - View admin resources
 *
 * VULNERABLE: Uses StaticHandler.create() with various mount points
 * which can be exploited for path traversal on Windows systems.
 */
public class DocumentServer extends AbstractVerticle {

    private static final Logger logger = LoggerFactory.getLogger(DocumentServer.class);
    private static final int PORT = 9999;

    public static void main(String[] args) {
        Vertx vertx = Vertx.vertx();
        vertx.deployVerticle(new DocumentServer());
    }

    @Override
    public void start(Promise<Void> startPromise) {
        Router router = Router.router(vertx);

        // Enable body handler for file uploads
        router.route().handler(BodyHandler.create());

        // API endpoints
        setupApiRoutes(router);

        // VULNERABLE: Static file serving with StaticHandler
        // This is the typical real-world pattern that causes CVE-2023-24815
        setupStaticFileHandlers(router);

        vertx.createHttpServer()
            .requestHandler(router)
            .listen(PORT, result -> {
                if (result.succeeded()) {
                    startPromise.complete();
                    logger.info("Document Management System started on port {}", PORT);
                    logger.info("  - Admin UI: http://localhost:{}/admin/", PORT);
                    logger.info("  - Documents: http://localhost:{}/documents/", PORT);
                    logger.info("  - Uploads: http://localhost:{}/uploads/", PORT);
                    logger.warn("⚠ VULNERABLE to CVE-2023-24815 (Path Traversal)");
                } else {
                    startPromise.fail(result.cause());
                }
            });
    }

    /**
     * Setup API routes for document management
     */
    private void setupApiRoutes(Router router) {
        // Health check endpoint
        router.get("/api/health").handler(ctx -> {
            ctx.response()
                .putHeader("content-type", "application/json")
                .end(new JsonObject()
                    .put("status", "healthy")
                    .put("service", "document-server")
                    .put("version", "1.0.0")
                    .encode());
        });

        // List documents API
        router.get("/api/documents").handler(ctx -> {
            ctx.response()
                .putHeader("content-type", "application/json")
                .end(new JsonObject()
                    .put("documents", new JsonObject()
                        .put("count", 42)
                        .put("path", "/documents"))
                    .encode());
        });

        // Upload endpoint (simplified)
        router.post("/api/upload").handler(ctx -> {
            logger.info("File upload request received");
            ctx.response()
                .putHeader("content-type", "application/json")
                .end(new JsonObject()
                    .put("success", true)
                    .put("message", "File uploaded")
                    .encode());
        });
    }

    /**
     * Setup static file handlers - VULNERABLE PATTERNS
     *
     * This demonstrates typical real-world usage patterns that are
     * vulnerable to CVE-2023-24815 path traversal.
     *
     * Signature: io.vertx.ext.web.handler.StaticHandler.create()
     */
    private void setupStaticFileHandlers(Router router) {
        // VULNERABLE PATTERN 1: Admin dashboard files
        // Real use case: Serving admin UI static assets (HTML, JS, CSS)
        router.route("/admin/*").handler(StaticHandler.create("admin"));

        // VULNERABLE PATTERN 2: User uploaded documents
        // Real use case: Serving files uploaded by users
        router.route("/uploads/*").handler(StaticHandler.create("uploads"));

        // VULNERABLE PATTERN 3: Company documents and training materials
        // Real use case: Shared company resources
        router.route("/documents/*").handler(StaticHandler.create("documents"));

        // VULNERABLE PATTERN 4: Public resources with default webroot
        // Real use case: Public-facing static assets
        router.route("/public/*").handler(StaticHandler.create());

        // VULNERABLE PATTERN 5: Catch-all static handler (most dangerous)
        // Real use case: Single-page application serving
        // This is common in SPAs where all routes should serve index.html
        router.route("/*").handler(StaticHandler.create("webroot"));

        logger.info("Static file handlers configured (VULNERABLE to path traversal)");
    }
}
