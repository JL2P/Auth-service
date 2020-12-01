package com.service.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;


@Component
@Order(1)
public class DBRunner implements ApplicationRunner{

    private final DataSource dataSource;

    DBRunner(DataSource dataSource){
        this.dataSource =dataSource;
    }

    private Logger logger = LoggerFactory.getLogger(DBRunner.class);

    @Override
    public void run(ApplicationArguments args) throws Exception {
        Connection connection = dataSource.getConnection();
        DatabaseMetaData dbMeta = connection.getMetaData();
        logger.info("=========================================");
        logger.info("DB URL : "+ dbMeta.getURL());
        logger.info("DB Username : "+dbMeta.getUserName());
        logger.info("DB DatabaseProductName : "+dbMeta.getDatabaseProductName());

        logger.info("=========================================");
    }

}
