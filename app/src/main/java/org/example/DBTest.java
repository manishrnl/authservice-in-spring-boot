package org.example;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DBTest {

    public static void main(String[] args) {
        // Use the default or environment override
        String host = System.getenv().getOrDefault("MYSQL_HOST", "127.0.0.1");
        String port = System.getenv().getOrDefault("MYSQL_PORT", "3307");
        String dbName = System.getenv().getOrDefault("MYSQL_DB", "authservice");
        String username = "root";
        String password = "Manish@2009";

        String url = String.format(
                "jdbc:mysql://%s:%s/%s?useSSL=false&useUnicode=yes&characterEncoding=UTF-8&allowPublicKeyRetrieval=true",
                host, port, dbName
        );

        try (Connection connection = DriverManager.getConnection(url, username, password)) {
            System.out.println("✅ Connection successful to database: " + dbName);
        } catch (SQLException e) {
            System.out.println("❌ Failed to connect to the database.");
            e.printStackTrace();
        }
    }
}


