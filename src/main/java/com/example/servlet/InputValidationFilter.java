package com.example.servlet;

import java.io.*;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.*;
import javax.servlet.http.*;
import com.googlecode.htmlcompressor.compressor.HtmlCompressor;

public class InputValidationFilter implements Filter {

    private static final Logger LOGGER = Logger.getLogger(InputValidationFilter.class.getName());
    private static final String INVALID_INPUT_MESSAGE = "Invalid input";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Perform input validation
        if (isValidRequest(httpRequest)) {
            chain.doFilter(request, response);
        } else {
            LOGGER.log(Level.WARNING, "Invalid input detected");
            httpResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, INVALID_INPUT_MESSAGE);
        }
    }

    private boolean isValidRequest(HttpServletRequest request) {
        // Validate URL parameters
        for (String param : request.getParameterMap().keySet()) {
            if (!isValidString(request.getParameter(param))) {
                return false;
            }
        }

        // Validate headers
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            if (!isValidString(request.getHeader(headerName))) {
                return false;
            }
        }

        // Validate cookies
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (!isValidString(cookie.getName()) || !isValidString(cookie.getValue())) {
                    return false;
                }
            }
        }

        return true;
    }

    private boolean isValidString(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        // Sanitize input by removing potentially harmful characters
        String sanitizedInput = sanitize(input);
        return !sanitizedInput.isEmpty();
    }

    public String sanitize(String input) {
        HtmlCompressor compressor = new HtmlCompressor();
        compressor.setRemoveComments(true);
        compressor.setRemoveIntertagSpaces(true);
        compressor.setRemoveQuotes(true);
        compressor.setRemoveMultiSpaces(true);
        return compressor.compress(input);
    }

}