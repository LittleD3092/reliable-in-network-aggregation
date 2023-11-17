# README

## 1. Introduction

This project is to implement a switch that adds two numbers together. The switch will receive two packets each with an operand. The switch will distinguish the two packets by a sequence number. The switch will add the two operands together and send the result to the third host.

## 2. Design

### 2.1. Topology

The topology is shown in the figure below.

```mermaid
graph LR
    h1["host 1: 10.0.1.1"]
    h2["host 2: 10.0.1.2"]
    h3["host 3: 10.0.1.3"]
    s1(("switch 1"))
    
    h1 --- s1
    h2 --- s1
    s1 --- h3
```

## 3. Implementation

TODO

## 4. Execute

The project is executed using Makefile. To start the project, run the following command.

```bash
make
```

A mininet console will be created, and you may exit it using `exit` command. To clean the project, run the following command.

```bash
make clean
```