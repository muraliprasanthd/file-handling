package com.example.servlet;

import java.io.*;
import java.sql.*;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;

@WebServlet("/filelist")
public class FileListServlet extends HttpServlet {

    private static final Logger LOGGER = Logger.getLogger(FileListServlet.class.getName());

    private Connection getConnection() throws SQLException {
        return new DatabaseHelper().getConnection();
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        List<Map<String, Object>> fileList = new ArrayList<>();

        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement("SELECT file_name, file_size, malware_status FROM files ORDER BY upload_time");
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                Map<String, Object> fileData = new HashMap<>();
                fileData.put("fileName", rs.getString("file_name"));
                fileData.put("fileSize", rs.getLong("file_size"));
                fileData.put("malwareStatus", rs.getString("malware_status"));
                fileList.add(fileData);
            }

            response.getWriter().write(generateHtml(fileList));

        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error retrieving files", e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("{\"error\": \"An error occurred while retrieving files.\"}");
        }
    }

    private String generateHtml(List<Map<String, Object>> fileList) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>");
        html.append("<html lang='en'>");
        html.append("<head>");
        html.append("<meta charset='UTF-8'>");
        html.append("<meta name='viewport' content='width=device-width, initial-scale=1.0'>"); // Mobile responsiveness
        html.append("<title>Uploaded Files</title>");
        html.append("<link rel='stylesheet' href='static/styleFiles.css'>");
        html.append("<style>");
        html.append("body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }");
        html.append("header { background-color: #333; color: white; padding: 1em; text-align: center; }");
        html.append("table { width: 100%; border-collapse: collapse; margin: 20px 0; }");
        html.append("table, th, td { border: 1px solid #ddd; }");
        html.append("th, td { padding: 12px; text-align: left; }");
        html.append("th { background-color: #4CAF50; color: white; }");
        html.append("tr:nth-child(even) { background-color: #f2f2f2; }");
        html.append("tr:hover { background-color: #ddd; }");
        html.append(".detected { color: red; font-weight: bold; }");
        html.append(".clean { color: green; font-weight: bold; }");
        html.append("</style>");
        html.append("</head>");
        html.append("<body>");
        html.append("<header><h1>Uploaded Files</h1></header>");
        html.append("<div class='container'>");
        html.append("<table>");
        html.append("<thead><tr><th>File Name</th><th>File Type</th><th>Malware Status</th></tr></thead>");
        html.append("<tbody>");

        for (Map<String, Object> file : fileList) {
            String fileName = (String) file.get("fileName");
            String fileType = getFileType(fileName);
            String malwareStatus = (String) file.get("malwareStatus");
            String statusClass = malwareStatus.equals("Malware detected") ? "detected" : "clean";
            html.append("<tr>");
            html.append("<td>").append(fileName).append("</td>");
            html.append("<td>").append(fileType).append("</td>");
            html.append("<td class='").append(statusClass).append("'>").append(malwareStatus).append("</td>");
            html.append("</tr>");
        }

        html.append("</tbody>");
        html.append("</table>");
        html.append("</div>");
        html.append("</body>");
        html.append("</html>");

        return html.toString();
    }

    private String getFileType(String fileName) {
        if (fileName.endsWith(".txt")) {
            return "Text File";
        } else if (fileName.endsWith(".jpg") || fileName.endsWith(".jpeg") || fileName.endsWith(".png") || fileName.endsWith(".gif") || fileName.endsWith(".bmp")) {
            return "Image File";
        } else if (fileName.endsWith(".pdf")) {
            return "PDF File";
        } else if (fileName.endsWith(".doc") || fileName.endsWith(".docx")) {
            return "Word Document";
        } else if (fileName.endsWith(".xls") || fileName.endsWith(".xlsx")) {
            return "Excel Spreadsheet";
        } else if (fileName.endsWith(".ppt") || fileName.endsWith(".pptx")) {
            return "PowerPoint Presentation";
        } else if (fileName.endsWith(".mp3") || fileName.endsWith(".wav") || fileName.endsWith(".flac")) {
            return "Audio File";
        } else if (fileName.endsWith(".mp4") || fileName.endsWith(".avi") || fileName.endsWith(".mkv") || fileName.endsWith(".mov")) {
            return "Video File";
        } else if (fileName.endsWith(".zip") || fileName.endsWith(".rar") || fileName.endsWith(".gz") || fileName.endsWith(".tar") || fileName.endsWith(".7z")) {
            return "Compressed File";
        } else if (fileName.endsWith(".html") || fileName.endsWith(".htm")) {
            return "HTML File";
        } else if (fileName.endsWith(".css")) {
            return "CSS File";
        } else if (fileName.endsWith(".js")) {
            return "JavaScript File";
        } else if (fileName.endsWith(".xml")) {
            return "XML File";
        } else if (fileName.endsWith(".json")) {
            return "JSON File";
        } else if (fileName.endsWith(".csv")) {
            return "CSV File";
        } else if (fileName.endsWith(".java")) {
            return "Java Source File";
        } else if (fileName.endsWith(".py")) {
            return "Python Script";
        } else if (fileName.endsWith(".c") || fileName.endsWith(".cpp") || fileName.endsWith(".h")) {
            return "C/C++ Source File";
        } else if (fileName.endsWith(".sh")) {
            return "Shell Script";
        } else if (fileName.endsWith(".exe")) {
            return "Executable File";
        } else {
            return "Unknown File Type";
        }
    }
}
