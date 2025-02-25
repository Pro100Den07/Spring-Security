package org.example;

import jdk.internal.misc.InnocuousThread;
import org.example.SpringBootApplication;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Main {
    public static void main(String[] args) {
        InnocuousThread SpringApplication;
        SpringApplication.run(Main.class, args);
    }
}
