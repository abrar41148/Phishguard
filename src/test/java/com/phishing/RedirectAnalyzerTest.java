package com.phishing;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.List;

public class RedirectAnalyzerTest {

    private static HttpServer server;
    private static int port;
    private static String baseUrl;

    @BeforeAll
    public static void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        port = server.getAddress().getPort();
        baseUrl = "http://localhost:" + port;

        // 1. Simple redirect: /start -> /end
        server.createContext("/start", exchange -> {
            exchange.getResponseHeaders().set("Location", baseUrl + "/end");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });

        // 2. Chain of 3: /chain1 -> /chain2 -> /chain3 -> /final
        server.createContext("/chain1", exchange -> {
            exchange.getResponseHeaders().set("Location", baseUrl + "/chain2");
            exchange.sendResponseHeaders(301, -1);
            exchange.close();
        });
        server.createContext("/chain2", exchange -> {
            exchange.getResponseHeaders().set("Location", baseUrl + "/chain3");
            exchange.sendResponseHeaders(301, -1);
            exchange.close();
        });
        server.createContext("/chain3", exchange -> {
            exchange.getResponseHeaders().set("Location", baseUrl + "/final");
            exchange.sendResponseHeaders(301, -1);
            exchange.close();
        });

        // 3. Circular: /loop1 -> /loop2 -> /loop1
        server.createContext("/loop1", exchange -> {
            exchange.getResponseHeaders().set("Location", baseUrl + "/loop2");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        server.createContext("/loop2", exchange -> {
            exchange.getResponseHeaders().set("Location", baseUrl + "/loop1");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });

        // 4. Relative redirect: /relative -> /final
        server.createContext("/relative", exchange -> {
            exchange.getResponseHeaders().set("Location", "/final");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });

        // 5. Final destination
        server.createContext("/final", exchange -> {
            exchange.sendResponseHeaders(200, 0);
            exchange.close();
        });
        server.createContext("/end", exchange -> {
            exchange.sendResponseHeaders(200, 0);
            exchange.close();
        });

        server.setExecutor(null);
        server.start();
    }

    @AfterAll
    public static void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    public void testSimpleRedirect() {
        RedirectAnalyzer analyzer = new RedirectAnalyzer();
        UrlTarget target = new UrlTarget(baseUrl + "/start");
        RiskReport report = new RiskReport(AnalysisResult.SAFE, "Test");

        analyzer.analyze(target, report);

        assertEquals(baseUrl + "/end", target.getResolvedUrl());
        assertTrue(report.getDetails().stream().anyMatch(d -> d.contains("Followed 1 redirect")));
    }

    @Test
    public void testRedirectChainScoring() {
        RedirectAnalyzer analyzer = new RedirectAnalyzer();
        UrlTarget target = new UrlTarget(baseUrl + "/chain1");
        RiskReport report = new RiskReport(AnalysisResult.SAFE, "Test");

        analyzer.analyze(target, report);

        assertEquals(baseUrl + "/final", target.getResolvedUrl());
        // 3 redirects should trigger excessive redirects score
        assertTrue(report.getScore() >= ConfigConstants.SCORE_EXCESSIVE_REDIRECTS);
        assertTrue(report.getDetails().stream().anyMatch(d -> d.contains("Excessive redirect chain length")));
    }

    @Test
    public void testCircularRedirect() {
        RedirectAnalyzer analyzer = new RedirectAnalyzer();
        UrlTarget target = new UrlTarget(baseUrl + "/loop1");
        RiskReport report = new RiskReport(AnalysisResult.SAFE, "Test");

        analyzer.analyze(target, report);

        // Should detect circular and stop
        assertTrue(report.getDetails().stream().anyMatch(d -> d.contains("Circular redirect detected")));
        assertTrue(report.getScore() > 0);
    }

    @Test
    public void testRelativeRedirect() {
        RedirectAnalyzer analyzer = new RedirectAnalyzer();
        UrlTarget target = new UrlTarget(baseUrl + "/relative");
        RiskReport report = new RiskReport(AnalysisResult.SAFE, "Test");

        analyzer.analyze(target, report);

        assertEquals(baseUrl + "/final", target.getResolvedUrl());
    }

    @Test
    public void testIpAddressDetection() {
        RedirectAnalyzer analyzer = new RedirectAnalyzer();
        // We simulate a URL that has an IP (localhost is 127.0.0.1 but URIs use names)
        // I will test the private helper method if I could, but I'll test it via analyze logic
        // if I create a context that points to 127.0.0.1
        
        server.createContext("/to-ip", exchange -> {
            exchange.getResponseHeaders().set("Location", "http://127.0.0.1:" + port + "/final");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });

        UrlTarget target = new UrlTarget(baseUrl + "/to-ip");
        RiskReport report = new RiskReport(AnalysisResult.SAFE, "Test");

        analyzer.analyze(target, report);

        assertTrue(report.getScore() >= ConfigConstants.SCORE_REDIRECT_TO_IP);
        assertTrue(report.getDetails().stream().anyMatch(d -> d.contains("Redirect to raw IP address detected")));
    }
}
