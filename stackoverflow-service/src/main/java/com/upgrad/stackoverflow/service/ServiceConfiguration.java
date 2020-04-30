package com.upgrad.stackoverflow.service;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * Enabling the component scan and entity scan of classes in the below mentioned
 *           "com.upgrad.stackoverflow.service"
 *           "com.upgrad.stackoverflow.service.entity"
 * packages respectively.
 */
@Configuration
@ComponentScan("com.upgrad.stackoverflow.service")
@EntityScan("com.upgrad.stackoverflow.service.entity")
public class ServiceConfiguration {
}
