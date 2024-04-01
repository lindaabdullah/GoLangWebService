use taskdb;

CREATE TABLE IF NOT EXISTS task (
    id int NOT NULL AUTO_INCREMENT PRIMARY KEY,
    Title varchar(255) DEFAULT NULL,
    Description varchar(255) DEFAULT NULL,
    Number int DEFAULT NULL,
    Result int DEFAULT NULL,
    Status varchar(255) DEFAULT NULL
);
