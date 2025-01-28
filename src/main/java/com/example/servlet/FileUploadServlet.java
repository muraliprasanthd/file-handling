package com.example.servlet;

import java.io.*;
import java.nio.file.*;
import java.sql.SQLException;
import java.util.*;
import java.util.regex.Pattern;
import javax.servlet.*;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.http.*;

@MultipartConfig(
        fileSizeThreshold = 1 * 1024 * 1024, // 1MB threshold for in-memory storage
        maxFileSize = 10 * 1024 * 1024,      // 10MB max file size
        maxRequestSize = 50 * 1024 * 1024    // 50MB max request size
)
public class FileUploadServlet extends HttpServlet {

    private static final String UPLOAD_DIR = "uploads";
    private static final Pattern SAFE_FILE_NAME = Pattern.compile("[a-zA-Z0-9._-]+");
    private final DatabaseHelper dbHelper = new DatabaseHelper();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("application/json");
        PrintWriter out = response.getWriter();
        List<String> errors = new ArrayList<>();
        HttpSession session = request.getSession(false);

        // Ensure user is authenticated
        if (session == null || session.getAttribute("user") == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            out.write("{\"error\": \"User is not authenticated.\"}");
            return;
        }

        String uploadPath = getServletContext().getRealPath("") + File.separator + UPLOAD_DIR;
        try {
            // Create upload directory if it doesn't exist
            Files.createDirectories(Paths.get(uploadPath));

            // Process uploaded files
            for (Part part : request.getParts()) {
                String originalFileName = extractFileName(part);
                if (originalFileName == null || !SAFE_FILE_NAME.matcher(originalFileName).matches()) {
                    continue;
                }

                // Generate secure file name
                String secureFileName = UUID.randomUUID() + "_" + originalFileName;
                Path filePath = Paths.get(uploadPath, secureFileName);

                // Save file to disk
                try (InputStream inputStream = part.getInputStream()) {
                    Files.copy(inputStream, filePath, StandardCopyOption.REPLACE_EXISTING);
                }

                // Validate file size
                if (Files.size(filePath) > 10 * 1024 * 1024) {
                    errors.add("File too large: " + originalFileName);
                    Files.delete(filePath);
                    continue;
                }

                // Perform malware scan
                boolean isMalware = performMalwareScan(filePath);
                String malwareStatus = isMalware ? "Malware detected" : "No malware detected";

                // Save file info in the database
                try (FileInputStream fis = new FileInputStream(filePath.toFile())) {
                    dbHelper.saveFileInfo(
                            (String) session.getAttribute("user"),
                            secureFileName,
                            Files.size(filePath),
                            fis,
                            malwareStatus
                    );
                }

                // Send response
                out.write("{\"fileName\": \"" + secureFileName + "\", \"status\": \"" + malwareStatus + "\"}");
            }

            if (!errors.isEmpty()) {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                out.write("{\"errors\": " + errors.toString() + "}");
            } else {
                response.setStatus(HttpServletResponse.SC_OK);
            }

        } catch (IOException | SQLException e) {
            log("Error processing file upload", e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            out.write("{\"error\": \"An internal server error occurred.\"}");
        } finally {
            out.close();
        }

        // Redirect to filelist
        response.sendRedirect(request.getContextPath() + "/filelist");
    }

    private boolean performMalwareScan(Path filePath) {
        MalwareScanner scanner = new MalwareScanner();
        return scanner.analyzeFile(filePath);
    }

    private String extractFileName(Part part) {
        String contentDisposition = part.getHeader("content-disposition");
        if (contentDisposition != null) {
            for (String content : contentDisposition.split(";")) {
                if (content.trim().startsWith("filename")) {
                    return content.substring(content.indexOf("=") + 1).trim().replace("\"", "");
                }
            }
        }
        return null;
    }
}
