from prompt_toolkit import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout.containers import VSplit, HSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.layout import Layout
from prompt_toolkit.widgets import TextArea, Frame
from prompt_toolkit.application import get_app

import threading

from scapy.all import (
    IntField,
    Packet,
    StrFixedLenField,
    XByteField,
    Ether,
    IP,
    TCP,
    send,
    sendp,
    sniff,
    bind_layers,
    socket
)

import sys
import os
import io
import time
import re
from contextlib import contextmanager

class Adder(Packet):
    name = "adder"
    fields_desc = [ StrFixedLenField("A", "A", length=1),
                    StrFixedLenField("D", "D", length=1),
                    XByteField("ver_maj", 0x00),
                    XByteField("ver_min", 0x01),
                    XByteField("seq_num", 0x00),
                    XByteField("is_result", 0x00),
                    IntField("num", 0x00) ]

bind_layers(TCP, Adder, dport=1234)

class AdderSender:
    def __init__(self, tui, dest_ip = '10.0.1.3', dest_port = 1234, src_port = 1234, dest_mac = '08:00:00:00:01:03'):
        self.src_port = src_port
        self.dest_mac = dest_mac
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.seq_num = 0
        self.tui = tui
        self.initial_seq = None

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Disable Nagle's algorithm
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        while True:
            try:
                self.socket.connect((self.dest_ip, self.dest_port))
                break
            except:
                self.tui.print("[SYSTEM] Connection failed. Retrying...")
                time.sleep(1)
                continue

    def __del__(self):
        self.socket.close()

    def listen_for_ack(self):
        def handle_pkt(pkt):
            if pkt.haslayer(TCP) and pkt[TCP].flags & 0x10 and pkt[TCP].flags & 0x03 == 0x00:
                if self.initial_seq is None:
                    self.initial_seq = pkt[TCP].seq
                relative_seq = pkt[TCP].seq - self.initial_seq
                self.tui.print("[ACK] seq_num: " + str(relative_seq))
            else:
                return

        sniff(filter='tcp and src port 1234', prn=handle_pkt, iface="eth0", store=False)

    def send(self, num_arr, seq_num = -1):
        if seq_num == -1:
            seq_num = self.seq_num
            self.seq_num += 1

        for num in num_arr:
            time.sleep(1)
            payload = Adder(
                A='A', D='D', ver_maj=0x00, ver_min=0x01,
                seq_num=seq_num, is_result=0x00, num=num
            )
            self.socket.send(payload.build())
            self.tui.print("[SEND] seq_num: " + str(seq_num) + " num: " + str(num))
            seq_num += 1

    def run_thread(self):
        t = threading.Thread(target=self.listen_for_ack)
        t.start()

class AdderReceiver:
    def __init__(self, tui, server_ip = '10.0.1.3', server_port = 1234, filter='port 1234'):
        self.filter = filter
        self.port = server_port
        self.tui = tui
        self.server_ip = server_ip
        self.current_client = 0
        self.client_capacity = 2

    def receive(self):
        def connection_thread(conn, addr):
            try:
                self.tui.print("[SYSTEM] Connection from " + str(addr))
                while True:
                    data = conn.recv(10)
                    # self.tui.print("[RECV-raw] data: " + str(data))
                    if data:
                        pkt = Adder(data)
                        self.tui.print(
                            "[RECV] seq_num: " + 
                            str(pkt.seq_num) + 
                            " num: " + str(pkt.num)
                        )
                    else:
                        self.tui.print("[SYSTEM] No more data from " + str(addr))
                        break
            finally:
                conn.close()
        while True:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tui.print("[SYSTEM] Starting up on " + self.server_ip + " port " + str(self.port))
            s.bind((self.server_ip, self.port))
            s.listen(self.client_capacity)
            while True:
                conn, addr = s.accept()
                self.current_client += 1
                t = threading.Thread(target=connection_thread, args=(conn, addr))
                t.start()
    def run_thread(self):
        t = threading.Thread(target=self.receive)
        t.start()

class Tui:
    def __init__(self):
        self.prompt = "[SEND/RECV?] (s/r)> "

        self.kb = KeyBindings()
        # Exit application with Ctrl-C or Ctrl-Q
        @self.kb.add('c-c')
        @self.kb.add('c-q')
        def _(event):
            event.app.exit()
                
        # Move focus with ctrl shift m and ctrl shift i
        @self.kb.add('c-up')
        def _(event):
            self.focus_message()
        @self.kb.add('c-down')
        def _(event):
            self.focus_input()

        # Prevent the user from deleting the prompt
        @self.kb.add('backspace')
        def _(event):
            if event.current_buffer.cursor_position <= len(self.prompt):
                event.current_buffer.cursor_position = len(self.prompt)
            else:
                event.current_buffer.delete_before_cursor()

        # Text areas for input in each "window"
        self.input_text_area = TextArea(
            text=self.prompt,
            multiline=False,
            wrap_lines=True,
            accept_handler=self.accept_input_handler
        )
        self.message_text_area = TextArea(
            text="",
            multiline=True,
            wrap_lines=True
        )

        # Creating two "windows" side by side using VSplit
        self.root_container = HSplit([
            Frame(self.message_text_area, title="Message"),
            Frame(self.input_text_area, title="Input"),
        ])

        # Creating the layout from our root container
        self.layout = Layout(self.root_container)

        # Initialize the application
        self.app = Application(layout=self.layout, key_bindings=self.kb, full_screen=True)

        # Move the focus to the input_text_area
        self.app.layout.focus(self.input_text_area)

        # Move the cursor to the end of the prompt
        self.input_text_area.buffer.cursor_position = len(self.prompt)

        self.agent = None

    def boot(self):
        while True:
            app = get_app()
            if app is not None:
                break
        ip_host_dict = {
            '10.0.1.1': 'h1',
            '10.0.1.2': 'h2',
            '10.0.1.3': 'h3',
        }
        ip = self.get_ip()
        if ip is None:
            self.print("[SYSTEM] Error getting IP address. Exiting...")
            sys.exit(1)
        rc_filename = ip_host_dict[ip] + ".rc"
        if not os.path.exists(rc_filename):
            self.print("[SYSTEM] No rc file \"" + rc_filename + "\" found.")
        else:
            self.run_rc_file(rc_filename)


    def get_ip(self):
        try:
            command_output = os.popen('ip addr show eth0').read()
            ip_regex = r'inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            match = re.search(ip_regex, command_output)
            if match:
                return match.group(1)
            else:
                return None
        except:
            return None

    def run_rc_file(self, file_path):
        with open(file_path, 'r') as f:
            for line in f:
                command = line.strip()
                self.accept_input_handler(command)

    def accept_input_handler(self, buffer):
        if type(buffer) == str:
            command = buffer
        else:
            command = buffer.text.split('> ')[-1]
        if self.prompt == "[SEND/RECV?] (s/r)> ":
            if command == "s":
                self.prompt = "[SEND] (num)> "
                self.agent = AdderSender(self, '10.0.1.3')
                self.agent.run_thread()
            elif command == "r":
                self.prompt = "[RECV]> "
                self.agent = AdderReceiver(self)
                self.agent.run_thread()
            else:
                self.print("Invalid command: " + command)
        elif self.prompt == "[SEND] (num)> ":
            num_arr = parse_num(command)
            self.agent.send(num_arr)
        elif self.prompt == "[RECV]> ":
            # Add receiver command here if needed
            parsed_cmd = command.split(' ')
            if parsed_cmd[0] == "echo":
                self.print(parsed_cmd[1])
        if type(buffer) != str:
            self.sync_prompt(buffer=buffer)
        else:
            self.sync_prompt(buffer=self.input_text_area.buffer)

    def sync_prompt(self, buffer):
        def print_prompt():
            buffer.text = self.prompt
            buffer.cursor_position = len(buffer.text)

        get_app().loop.call_soon(print_prompt)

    def focus_input(self):
        self.app.layout.focus(self.input_text_area)

    def focus_message(self):
        self.app.layout.focus(self.message_text_area)

    def print(self, text, end="\n"):
        def print_text():
            self.message_text_area.text += text + end
            self.message_text_area.buffer.cursor_position = len(self.message_text_area.buffer.text)
        # Schedule the print_text
        get_app().loop.call_soon(print_text)


    def run(self):
        boot_thread = threading.Thread(target=self.boot)
        boot_thread.start()
        self.app.run()

def parse_num(num):
    if num[0] == '[' and num[-1] == ']':
        num = num[1:-1]
        if ',' in num:
            return [int(x) for x in num.split(',')]
        elif ' ' in num:
            return [int(x) for x in num.split(' ')]
        elif ':' in num:
            arr = num.split(':')
            if len(arr) == 2:
                return list(range(int(arr[0]), int(arr[1])))
            elif len(arr) == 3:
                return list(range(int(arr[0]), int(arr[1]), int(arr[2])))
        else:
            return [int(num)]
    else:
        return [int(num)]


if __name__ == "__main__":
    tui = Tui()
    tui.run()