# README

## 1. Introduction

This project is to implement a switch that aggregates numbers from all hosts together. The switch will receive packets each with a number in the payload. The switch will aggregate packets with the same sequence number. After all hosts have sent the packets with the same sequence number, the switch will send the aggregated number to the receiver. The receiver will receive the aggregated number and print it out.

## 2. Design

### 2.1. Topology

The topology is shown in the figure below.

```mermaid
graph LR
    h1["host 1: 10.0.1.1"]
    h2["host 2: 10.0.1.2"]
    h3["host 3: 10.0.1.3"]
    h4["host 4: 10.0.1.4"]
    h5["host 5: 10.0.1.5"]
    s1(("switch 1"))
    
    h1 --- s1
    h2 --- s1
    h3 --- s1
    h4 --- s1
    s1 --- h5
```

## 3. Implementation

The p4 code can be separated into two parts: the TCP cheater and the ring buffer. The TCP cheater is used to record the sequence number and modify the TCP header. The ring buffer is used to store the payload of the packet.

The TCP cheater has the following flowchart:

```mermaid
flowchart TD
    recv(("收到封包"))
    if_ack{"是ack還是\ntcp payload"}
    multicast(("multicast並\n更新ring buffer\n的index"))
    if_first{"是host送來的\n第一個封包嗎"}
    record_ini_seq["紀錄初始sequence number, \nack number, source port\n並將相對的sequence number設為1"]
    calc_relative_seq["計算此封包的相對sequence number"]
    ring_buffer["依據相對的sequence number\n將payload存進ring buffer"]
    if_aggr_done{"aggregate\n結束了嗎"}
    send(("送到receiver"))
    drop(("丟棄封包"))

    recv --> if_ack
    
    if_ack -- "ack" --> multicast
    if_ack -- "tcp payload" --> if_first
    
    if_first -- "是" --> record_ini_seq
    if_first -- "否" --> calc_relative_seq

    record_ini_seq --> ring_buffer
    calc_relative_seq --> ring_buffer

    ring_buffer --> if_aggr_done
    if_aggr_done -- "是" --> send
    if_aggr_done -- "否" --> drop
```

The ring buffer has the following flowchart:

```mermaid
flowchart TD
    recv_ack(("收到ack"))
    update_min_index(("更新min_index"))
    recv(("收到payload"))
    get_index["從相對的sequence number\n得到index"]
    if_case{"這個sequence number\n處於哪一個區間?"}
    drop1(("丟棄封包"))
    drop2(("丟棄封包"))
    aggr["aggregate數字\n並記錄此host送過了"]
    if_buffer_full{"buffer滿了嗎"}
    aggr_new["紀錄sequence number、\npayload與host"]
    if_aggr_done{"所有host\n都送過了嗎"}
    send(("送到receiver"))

    recv_ack --> update_min_index
    recv --> get_index
    get_index --> if_case

    if_case -- "被ack過(小於min_seq)" --> drop1
    if_case -- "正在aggregate\n(介於min_seq和max_seq)" --> aggr
    if_case -- "新的數字(大於max_seq)" --> if_buffer_full

    aggr --> if_aggr_done
    if_aggr_done -- "是" --> send

    if_buffer_full -- "是" --> drop2
    if_buffer_full -- "否" --> aggr_new --> drop2
```

## 4. Execute

The project is executed using Makefile. To start the project, run the following command.

```bash
make
```

A mininet console will be created, and you may exit it using `exit` command. 

Use the following command to open the xterm of the hosts.

```bash
xterm h1 h2 h3 h4 h5
```

To run the test, run the following command in each xterm.

```bash
python3 adder.py
```

> Note: It is recommended to run `adder.py` in `h5` after all other hosts have run `adder.py` and are waiting for `h5`.
> This is because `h5` is the receiver, and starting it first will cause several senders to send packets first, which cause the starting time of each sender to be different.

To clean the project, run the following command.

```bash
make clean
```