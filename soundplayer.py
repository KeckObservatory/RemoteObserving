#!/usr/bin/env python3

import argparse
import getpass
import os
import platform
import re
import shlex
import socket
import subprocess
import sys
import time

from pathlib import Path


VERSION = "2.0"


class SoundPlayClient:

    def __init__(self, args):
        self.args = args
        self.host = "localhost"
        self.port = 9798
        self.volume = 50
        self.workdir = Path.home() / ".soundboard"
        self.take_connection = False
        self.check_local_sound = False
        self.use_external_player = True
        self.blocking_external_player = False
        self.tags = []
        self.sock = None
        self.sockfile = None
        self.play_template = self.args.px.split()
        self.scale_volume_factor = 1.0

    ##################################################################
    # Utility functions
    ##################################################################

    @staticmethod
    def timestamp():
        return time.strftime("%H:%M:%S %a")

    @staticmethod
    def quote_text(text):
        out = []
        for ch in text:
            if ch == "\\":
                out.append("\\\\")
            elif ch == "\n":
                out.append("\\n")
            elif ch == "\r":
                out.append("\\r")
            elif ord(ch) < 32 or ord(ch) > 126:
                out.append(f"\\{ord(ch):03o}")
            else:
                out.append(ch)
        return "".join(out)

    def compose_play_response(self, errors, messages):
        text = "\n".join(messages)
        return f"PLAYRESPONSE {errors} {self.quote_text(text)}"

    ##################################################################
    # Volume handling
    ##################################################################

    def scale_volume(self, volume):
        scaled = volume * self.scale_volume_factor
        if self.scale_volume_factor * 100 >= 10:
            return str(round(scaled))
        return f"{scaled:.2f}"

    ##################################################################
    # File cache
    ##################################################################

    def save_sound(self, filename, content):
        self.workdir.mkdir(parents=True, exist_ok=True)
        path = self.workdir / filename
        with open(path, "wb") as out:
            out.write(content)
        return path

    ##################################################################
    # Playback
    ##################################################################

    def play_sound(self, filename):
        path = str(self.workdir / filename)
        volume = self.scale_volume(self.volume)
        command = []
        for arg in self.play_template:
            arg = arg.replace("%v", volume)
            arg = arg.replace("%s", path)
            command.append(arg)
        msgs = [f"Command={' '.join(command)}"]
        try:
            if self.blocking_external_player:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                )
                if result.returncode:
                    return 1, [result.stderr.strip()]

                return 0, msgs
            else:
                subprocess.Popen(
                    command,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return 0, msgs
        except Exception as exc:
            return 1, [str(exc)]

    ##################################################################
    # Socket helpers
    ##################################################################

    @staticmethod
    def receive_exact(sock, nbytes):
        data = bytearray()
        while len(data) < nbytes:
            chunk = sock.recv(nbytes - len(data))
            if not chunk:
                raise EOFError("socket closed")
            data.extend(chunk)
        return bytes(data)

    def send_line(self, text):
        self.sock.sendall((text + "\n").encode())

    ##################################################################
    # Connection
    ##################################################################

    def connect(self):
        while True:
            try:
                self.sock = socket.create_connection(
                    (self.host, self.port)
                )
                self.sockfile = self.sock.makefile(
                    "rb",
                    buffering=0
                )
                break
            except Exception as exc:
                print(
                    f"Cannot connect to {self.host}:{self.port}: "
                    f"{exc}"
                )
                print("Retrying in 30 seconds")
                time.sleep(30)
        print(f"Connected to {self.host}:{self.port}")
        self.register_player()

    def register_player(self):
        hostname = socket.gethostname()
        user = getpass.getuser()
        pid = os.getpid()
        msg = (
            f"PLAYERINFO "
            f"{hostname} "
            f"{user} "
            f"{pid} "
            f"{int(self.take_connection)} "
            f"{' '.join(self.tags)}"
        )
        self.send_line(msg)

    ##################################################################
    # Protocol handling
    ##################################################################

    PLAY_RE = re.compile(r"^\s*PLAY\s+(\S+)\s*$")
    PLAY_CACHE_RE = re.compile(
        r"^\s*PLAY\s+(\S+)\s+(\d+):\s*$"
    )
    VOLUME_RE = re.compile(
        r"^\s*VOLUME\s+(\d+)\s*$"
    )
    HELLO_RE = re.compile(r"^\s*HELLO")
    GOODBYE_RE = re.compile(
        r"^\s*GOODBYE\s+(.*)$"
    )

    def process_line(self, line):
        line = line.rstrip("\n")

        ##################################################################
        # PLAY existing sound
        ##################################################################
        m = self.PLAY_RE.match(line)
        if m:
            filename = m.group(1)
            err, msgs = self.play_sound(filename)
            self.send_line(
                self.compose_play_response(err, msgs)
            )
            return

        ##################################################################
        # PLAY + cache data
        ##################################################################
        m = self.PLAY_CACHE_RE.match(line)
        if m:
            filename = m.group(1)
            nbytes = int(m.group(2))
            print(
                f"{self.timestamp()} "
                f"receiving {nbytes} bytes"
            )
            sound = self.receive_exact(
                self.sock,
                nbytes
            )
            end1 = self.sockfile.readline().decode().strip()
            end2 = self.sockfile.readline().decode().strip()
            if end1 != "" or end2 != "END_OF_SOUND":
                self.send_line(
                    "ERR expected END_OF_SOUND"
                )
                return
            self.save_sound(filename, sound)
            err, msgs = self.play_sound(filename)
            self.send_line(
                self.compose_play_response(err, msgs)
            )
            return

        ##################################################################
        # volume
        ##################################################################
        m = self.VOLUME_RE.match(line)
        if m:
            self.volume = int(m.group(1))
            self.send_line("OK")
            return

        ##################################################################
        # hello
        ##################################################################
        if self.HELLO_RE.match(line):
            self.send_line("HELLO to you, too.")
            return

        ##################################################################
        # goodbye
        ##################################################################
        m = self.GOODBYE_RE.match(line)
        if m:
            print("Server requested shutdown")
            sys.exit(0)
        print("Unknown command:", line)
        self.send_line(f"ERR Unknown command: {line}")

    ##################################################################
    # Main loop
    ##################################################################
    def run(self):
        self.workdir.mkdir(
            parents=True,
            exist_ok=True,
        )
        while True:
            try:
                self.connect()
                while True:
                    raw = self.sockfile.readline()
                    if not raw:
                        raise EOFError(
                            "connection closed"
                        )
                    self.process_line(
                        raw.decode("utf-8", "replace")
                    )
            except Exception as exc:
                print("Disconnected:", exc)
                try:
                    self.sock.close()
                except Exception:
                    pass
                print("Reconnect in 30 seconds")
                time.sleep(30)


    def play_local_test(self):
        self.play_sound(Path(__file__).parent / "testsound.au")


def build_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s",
        metavar="host[:port]",
    )
    parser.add_argument(
        "-t",
        action="store_true",
    )
    parser.add_argument(
        "-d",
        metavar="DIR",
    )
    parser.add_argument(
        "-ps",
        action="store_true",
    )
    parser.add_argument(
        "-pv",
        type=float,
    )
    parser.add_argument(
        "-px",
        metavar="COMMAND",
        nargs="?",
    )
    parser.add_argument(
        "-T",
        action="append",
        default=[],
    )
    parser.add_argument(
        "-version",
        action="store_true",
    )
    parser.add_argument(
        "-l",
        action="store_true",
        help="Play local test sound and exit",
    )
    return parser



def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.version:
        print(VERSION)
        return

    client = SoundPlayClient(args)

    if args.l:
        rc = client.play_local_test()
        sys.exit(rc)

    if args.s:

        if ":" in args.s:
            host, port = args.s.split(":", 1)
            client.host = host
            client.port = int(port)
        else:
            client.host = args.s

    if args.d:
        client.workdir = Path(args.d)

    if args.t:
        client.take_connection = True

    if args.ps:
        client.blocking_external_player = True

    if args.pv is not None:
        client.scale_volume_factor = args.pv

    if args.px:
        client.play_template = shlex.split(args.px)

    client.tags = args.T

    client.run()


if __name__ == "__main__":
    main()
