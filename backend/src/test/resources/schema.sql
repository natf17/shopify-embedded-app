CREATE TABLE shopify_oauth_access_tokens (
    id INT PRIMARY KEY AUTO_INCREMENT,
    shop VARCHAR(100) NOT NULL,
    access_token VARCHAR(512) NOT NULL,
    scope VARCHAR(512),
    date_created TIMESTAMP
);