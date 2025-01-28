package com.example.servlet;

import java.io.InputStream;
import java.sql.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DatabaseHelper {

    private static final Logger LOGGER = Logger.getLogger(DatabaseHelper.class.getName());
    private static final String URL = "jdbc:mysql://localhost:3306/file_handling?useSSL=false&serverTimezone=UTC";
    private static final String USER = "root";
    private static final String PASSWORD = "";

    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            LOGGER.log(Level.SEVERE, "MySQL JDBC Driver not found", e);
        }
    }

    /**
     * Get a connection to the database.
     *
     * @return a Connection object
     * @throws SQLException if a database access error occurs
     */
    public Connection getConnection() throws SQLException {
        return DriverManager.getConnection(URL, USER, PASSWORD);
    }

    /**
     * Save file information to the database.
     *
     * @param username      the username of the user
     * @param fileName      the name of the file
     * @param fileSize      the size of the file
     * @param fileData      the file data as an InputStream
     * @param malwareStatus the malware status of the file
     * @throws SQLException if a database access error occurs
     */
    public void saveFileInfo(String username, String fileName, long fileSize, InputStream fileData, String malwareStatus) throws SQLException {
        String sql = "INSERT INTO files (user_id, file_name, file_size, file_data, malware_status) VALUES ((SELECT id FROM users WHERE username = ?), ?, ?, ?, ?)";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, username);
            stmt.setString(2, fileName);
            stmt.setLong(3, fileSize);
            stmt.setBlob(4, fileData);
            stmt.setString(5, malwareStatus);
            stmt.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error saving file information", e);
            throw e;
        }
    }
}
