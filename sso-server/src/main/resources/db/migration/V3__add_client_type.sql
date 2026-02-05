-- Add client type column (works in any environment)
-- Use dynamic SQL to check if column exists

SET
    @col_exists = (
        SELECT COUNT(*)
        FROM information_schema.COLUMNS
        WHERE
            TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME = 'oauth_clients'
            AND COLUMN_NAME = 'client_type'
    );

-- Execute ADD or MODIFY based on column existence
SET
    @sql = IF(
        @col_exists = 0,
        'ALTER TABLE oauth_clients ADD COLUMN client_type VARCHAR(20) NOT NULL DEFAULT ''CONFIDENTIAL'' COMMENT ''Client type: PUBLIC or CONFIDENTIAL''',
        'ALTER TABLE oauth_clients MODIFY COLUMN client_type VARCHAR(20) NOT NULL DEFAULT ''CONFIDENTIAL'' COMMENT ''Client type: PUBLIC or CONFIDENTIAL'''
    );

PREPARE stmt FROM @sql;

EXECUTE stmt;

DEALLOCATE PREPARE stmt;

-- Set default type for existing clients
UPDATE oauth_clients
SET
    client_type = 'CONFIDENTIAL'
WHERE
    client_type IS NULL
    OR client_type = '';