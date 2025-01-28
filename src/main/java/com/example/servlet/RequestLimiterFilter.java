package com.example.servlet;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

public class RequestLimiterFilter implements Filter {

    private static final int MAX_REQUESTS = 20;
    private AtomicInteger requestCount = new AtomicInteger(0);

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        if (requestCount.incrementAndGet() <= MAX_REQUESTS) {
                chain.doFilter(request, response);
        } else {
            httpResponse.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "Too many requests");
        }
    }
}
