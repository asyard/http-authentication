package com.asy.http.server.core;

import com.asy.http.server.filter.AuthenticationControlFilter;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.logging.Logger;

/**
 * Created by asy
 */
public class BasicHttpServer {

    private static final Logger logger = Logger.getLogger(BasicHttpServer.class.getName());

    public BasicHttpServer(int port, String contextPath) throws IOException {
        HttpServer httpServer = HttpServer.create(new InetSocketAddress(port), 0);
        HttpContext httpContext = httpServer.createContext("/" + contextPath, new BasicHttpServerHandler());
        httpContext.getFilters() .add(new AuthenticationControlFilter()); // Add AuthenticationControlFilter to the context
        httpServer.setExecutor(null); // creates a default executor
        httpServer.start();
        logger.info("Server started and listening port "+ port);
    }


    class BasicHttpServerHandler implements HttpHandler {
        public void handle(HttpExchange httpExchange) throws IOException {
            String response = "This is the response";
            httpExchange.sendResponseHeaders(200, response.length());
            OutputStream os = httpExchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

}
