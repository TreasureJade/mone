package run.mone.mcp.mysql.function;

import lombok.Data;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import run.mone.hive.mcp.function.McpFunction;
import run.mone.hive.mcp.spec.McpSchema;

import java.io.File;
import java.sql.*;
import java.util.List;
import java.util.Map;

@Data
@Slf4j
public class SqliteFunction implements McpFunction {

    private String name = "stream_sqlite_executor";

    private String desc = "Execute SQLite operations (query, update, DDL)";

    private String sqlToolSchema = """
            {
                "type": "object",
                "properties": {
                    "type": {
                        "type": "string",
                        "enum": ["query", "update", "ddl"],
                        "description": "Type of SQL operation to execute"
                     },
                     "sql": {
                         "type": "string",
                         "description": "SQL statement to execute"
                    },
                    "path": {
                        "type": "string",
                        "description": "Database file path (optional, defaults to ~/sqlite.db)"
                    }
                },
                "required": ["type", "sql"]
            }
            """;
    private Connection connection;

    public SqliteFunction() {
        log.info("Initializing SqliteFunction...");
    }

    @Override
    public String getDesc() {
        return desc;
    }

    @Override
    public String getName() {
        return name;
    }

    private synchronized void ensureConnection(String dbPath) {
        if (connection != null) {
            try {
                if (!connection.isClosed()) {
                    return;
                }
            } catch (SQLException e) {
                log.warn("Connection validation failed", e);
            }
        }

        if (dbPath == null || dbPath.trim().isEmpty()) {
            String defaultPath = System.getProperty("user.home") + File.separator + "sqlite.db";
            dbPath = System.getenv().getOrDefault("SQLITE_DB_PATH", defaultPath);
        }

        try {
            log.info("Attempting to connect to SQLite database at {}...", dbPath);
            connection = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
            log.info("Successfully connected to SQLite database");
        } catch (SQLException e) {
            log.error("Failed to connect to SQLite database", e);
            throw new RuntimeException(e);
        }
    }

    @SneakyThrows
    @Override
    public Flux<McpSchema.CallToolResult> apply(Map<String, Object> args) {
        String type = (String) args.get("type");
        String sql = (String) args.get("sql");
        String path = (String) args.get("path");
        
        if (sql == null || sql.trim().isEmpty()) {
            log.error("Empty SQL provided");
            throw new IllegalArgumentException("SQL is required");
        }
        log.info("Executing {} operation: {}", type, sql);
        ensureConnection(path);

        try {
            switch (type.toLowerCase()) {
                case "query":
                    return executeQuery(sql);
                case "update":
                    return executeUpdate(sql);
                case "ddl":
                    return executeDDL(sql);
                default:
                    throw new IllegalArgumentException("Unsupported operation type: " + type);
            }
        } catch (Throwable ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    private Flux<McpSchema.CallToolResult> executeQuery(String sql) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.setMaxRows(100);
            ResultSet rs = stmt.executeQuery(sql);
            StringBuilder result = new StringBuilder();
            ResultSetMetaData metaData = rs.getMetaData();
            int columnCount = metaData.getColumnCount();

            // Add column names
            for (int i = 1; i <= columnCount; i++) {
                result.append(metaData.getColumnName(i)).append("\t");
            }
            result.append("\n");

            // Add data rows
            while (rs.next()) {
                for (int i = 1; i <= columnCount; i++) {
                    result.append(rs.getString(i)).append("\t");
                }
                result.append("\n");
            }

            log.info("Successfully executed query");
            return Flux.just(new McpSchema.CallToolResult(
                    List.of(new McpSchema.TextContent(result.toString())),
                    false
            ));
        }
    }

    private Flux<McpSchema.CallToolResult> executeUpdate(String sql) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            int affected = stmt.executeUpdate(sql);
            log.info("Successfully executed update. Affected rows: {}", affected);
            return Flux.just(new McpSchema.CallToolResult(
                    List.of(new McpSchema.TextContent("Affected rows: " + affected)),
                    false
            ));
        }
    }

    private Flux<McpSchema.CallToolResult> executeDDL(String sql) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
            log.info("Successfully executed DDL");
            return Flux.just(new McpSchema.CallToolResult(
                    List.of(new McpSchema.TextContent("DDL executed successfully")),
                    false
            ));
        }
    }

    @Override
    public String getToolScheme() {
        return sqlToolSchema;
    }
}
