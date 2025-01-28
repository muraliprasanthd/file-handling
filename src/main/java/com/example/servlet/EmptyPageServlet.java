package com.example.servlet;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class EmptyPageServlet extends HttpServlet {

    private static final Logger LOGGER = Logger.getLogger(EmptyPageServlet.class.getName());
    private static final String EMPTY_PAGE_URL = "/empty.html";

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            request.getRequestDispatcher(EMPTY_PAGE_URL).forward(request, response);
        } catch (ServletException | IOException e) {
            LOGGER.log(Level.SEVERE, "Error forwarding to empty page", e);
            throw e;
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            request.getRequestDispatcher(EMPTY_PAGE_URL).forward(request, response);
        } catch (ServletException | IOException e) {
            LOGGER.log(Level.SEVERE, "Error forwarding to empty page", e);
            throw e;
        }
    }
}
