-- Provision the database as a DBA. Application automatically creates its metrics table.
CREATE DATABASE IF NOT EXISTS ascend_monitor CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
-- Provision a dedicated MySQL writer account securely using your DBA process.
-- Required privileges on ascend_monitor.*: SELECT, INSERT, UPDATE, CREATE.
