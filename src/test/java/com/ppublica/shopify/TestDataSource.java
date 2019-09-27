package com.ppublica.shopify;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

public class TestDataSource extends DriverManagerDataSource implements DisposableBean {
	String name;

	public TestDataSource(String databaseName) {
		name = databaseName;
		System.out.println("Creating database: " + name);
		setDriverClassName("org.hsqldb.jdbcDriver");
		setUrl("jdbc:hsqldb:mem:" + databaseName);
		setUsername("sa");
		setPassword("");
	}

	public void destroy() {
		System.out.println("Shutting down database: " + name);
		new JdbcTemplate(this).execute("SHUTDOWN");
	}
}
