"""
VANTA//FLOW - Synthetic Diode Traffic Generator

Simulates the unidirectional UDP stream that a real hardware data diode
would forward. Sends realistic "benign" traffic most of the time, with
periodic injected "malware exfiltration" bursts:
  - benign:  moderate entropy (text/HTTP-like), irregular human-ish timing
  - attack:  near-random high-entropy payload, tight mechanized IAT (<5ms),
             mimicking a Cobalt-Strike-style C2 beacon micro-burst

Every packet is prefixed with an 8-byte big-endian sequence number. This
is a real framing header (matches the "custom unidirectional framing"
your handbook mentions in Module 1.2) and lets the receiver detect
genuinely dropped UDP datagrams -- something otherwise invisible on a
diode, since there's no retransmit and no ACK path. --drop-rate lets you
demonstrate that counter moving instead of it sitting at 0 the whole demo.

Run this in a second terminal while main.py is running:
    python synthetic_generator.py --target 127.0.0.1 --port 9999
"""
import argparse
import random
import socket
import struct
import time

BENIGN_SNIPPETS = [
    b"GET /api/v1/telemetry HTTP/1.1\r\nHost: plant-sensor-04.local\r\n\r\n",
    b"turbine_rpm=3400;pressure_psi=812;status=nominal;ts=",
    b"{\"sensor\":\"pressure-12\",\"value\":88.4,\"unit\":\"psi\"}",
    b"SYSLOG: heartbeat ok node=substation-east seq=",
]


def make_benign_payload() -> bytes:
    base = random.choice(BENIGN_SNIPPETS)
    # add a little natural variability so entropy isn't perfectly static
    noise = bytes(random.randint(32, 122) for _ in range(random.randint(5, 40)))
    return base + noise + str(time.time()).encode()


def make_attack_payload() -> bytes:
    # High-entropy pseudo-random bytes -- simulates AES-encrypted C2 traffic
    length = random.choice([64, 512, 1420])
    return bytes(random.randint(0, 255) for _ in range(length))


def make_padded_evasion_payload() -> bytes:
    """Entropy-smoothing evasion attempt: mixes high-entropy ciphertext with
    low-entropy null padding to try to sneak the *global* mean under the
    3-sigma gate. This is what Q&A #4 in the handbook is about -- use it to
    show the judges your sliding-window-variance defense actually catches it."""
    ciphertext = bytes(random.randint(0, 255) for _ in range(200))
    padding = bytes([0x00] * 300)
    return ciphertext + padding


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--attack-every", type=float, default=20.0,
                         help="seconds between injected attack bursts")
    parser.add_argument("--burst-size", type=int, default=15)
    parser.add_argument("--drop-rate", type=float, default=0.0,
                         help="fraction of packets to silently NOT send (0.01 = 1%%), "
                              "to demo the buffer-drop counter on the dashboard")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[generator] sending simulated diode traffic to {args.target}:{args.port}")
    print(f"[generator] attack burst every ~{args.attack_every}s, {args.burst_size} packets/burst")
    if args.drop_rate > 0:
        print(f"[generator] simulating {args.drop_rate*100:.1f}% packet loss")

    seq = 0

    def send(payload: bytes):
        nonlocal seq
        framed = struct.pack(">Q", seq) + payload
        seq += 1
        if args.drop_rate > 0 and random.random() < args.drop_rate:
            return  # simulate a lost datagram -- seq still advances, receiver sees the gap
        sock.sendto(framed, (args.target, args.port))

    last_attack = time.time()
    try:
        while True:
            now = time.time()
            if now - last_attack >= args.attack_every:
                mode = random.choice(["c2_beacon", "padded_evasion"])
                print(f"[generator] >>> injecting {mode} burst ({args.burst_size} packets)")
                for _ in range(args.burst_size):
                    payload = (
                        make_padded_evasion_payload()
                        if mode == "padded_evasion"
                        else make_attack_payload()
                    )
                    send(payload)
                    time.sleep(random.uniform(0.001, 0.004))  # <4ms mechanized IAT
                last_attack = now
            else:
                send(make_benign_payload())
                time.sleep(random.uniform(0.05, 0.4))  # irregular human-ish timing
    except KeyboardInterrupt:
        print("\n[generator] stopped.")


if __name__ == "__main__":
    main()
