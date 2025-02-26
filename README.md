# wi-fi-pass-crack

`wi-fi-pass-crack` is a cutting-edge, open-source Wi-Fi security testing tool developed for **educational purposes only**. Created by **It Is Unique Official**, this tool pushes the boundaries of Wi-Fi password cracking by integrating advanced techniques such as AI-driven password prediction, targeted deauthentication attacks, real-time handshake capture, and multi-adapter parallel processing. It is uniquely designed to demonstrate the vulnerabilities in Wi-Fi networks while providing a robust platform for security researchers and enthusiasts to learn and experiment responsibly.

This tool stands out due to its combination of artificial intelligence, stealth capabilities, and seamless integration with industry-standard tools like `hashcat`. Whether you're a student, a cybersecurity professional, or a hobbyist, `wi-fi-pass-crack` offers an unparalleled educational experience in understanding Wi-Fi security.

---

## Developed By
- **Developer**: It Is Unique Official
- **Contact**: [itisuniqueofficial](https://github.com/itisuniqueofficial) 
- **Date**: February 26, 2025  
- **Affiliation**: Developed as an independent project under the xAI-inspired ethos of advancing human scientific discovery through AI.

---

## Why It’s Unique
`wi-fi-pass-crack` distinguishes itself from other Wi-Fi cracking tools with the following innovative features:
1. **AI-Driven Password Prediction**: Leverages a simulated character-level RNN (based on Markov chains) to generate highly probable passwords tailored to the target network.
2. **Targeted Deauthentication**: Allows precise disconnection of specific devices by MAC address, enhancing efficiency and reducing collateral impact.
3. **Multi-Adapter Support**: Utilizes multiple Wi-Fi adapters simultaneously for faster scanning, cracking, and packet capture.
4. **Real-Time Handshake Analysis**: Captures WPA/WPA2 handshakes and integrates with `hashcat` for professional-grade cracking.
5. **Stealth Mode**: Implements MAC address spoofing and randomized packet timing to minimize detection by network administrators.
6. **Modular Design**: Separates password generation, network monitoring, and cracking into reusable components, making it extensible and easy to upgrade.

Unlike traditional tools like `aircrack-ng` or `Wifite`, `wi-fi-pass-crack` combines modern programming paradigms (asyncio, multi-threading) with AI techniques, offering a fresh and powerful approach to Wi-Fi security testing.

---

## Features
### Core Features
- **AI Password Prediction**: Generates passwords using a simulated AI model, prioritizing patterns derived from SSID hints, common words, and captured data.
- **Targeted Deauthentication**: Disconnects all users or a specific device from the target network to force reconnection attempts.
- **Handshake Capture & Cracking**: Sniffs WPA/WPA2 handshake packets and uses `hashcat` to extract passwords.
- **Multi-Adapter Parallelism**: Leverages multiple Wi-Fi adapters for simultaneous scanning and cracking, doubling efficiency with each additional adapter.
- **Real-Time Network Monitoring**: Tracks signal strength and connection status during operations.
- **Stealth Enhancements**: Spoofs MAC addresses and randomizes packet intervals to evade detection.

### Additional Features
- **CLI Interface**: Command-line options for advanced control and automation.
- **Result Persistence**: Saves cracked passwords and metadata to a JSON file (`cracked_networks.json`).
- **Logging**: Detailed logs (`wi-fi-pass-crack.log`) for debugging and analysis.
- **Customizable Password Generation**: Allows user-defined wordlists and custom keywords for tailored attacks.

---

## Prerequisites
### Software
- **Python**: 3.8 or higher
- **Libraries**:
  - `pywifi`: Wi-Fi interface management
  - `tqdm`: Progress bars
  - `asyncio`: Asynchronous operations
  - `aiofiles`: Async file I/O
  - `psutil`: System resource monitoring
  - `numpy`: Probability calculations
  - `scapy`: Packet crafting and sniffing
  - `argparse`: CLI parsing
- **Optional**: `hashcat` (for handshake cracking)

### Hardware
- **Wi-Fi Adapter(s)**: At least one adapter supporting monitor mode (e.g., Atheros AR9271, RTL8187). Multiple adapters recommended for parallel operations.
- **Operating System**: Windows (tested), Linux/macOS (adaptable with minor changes).

### Dependencies
- **Npcap** (Windows) or **libpcap** (Linux/macOS): Required for `scapy` packet manipulation.
- **Administrative Privileges**: Needed for adapter control and packet injection.

---

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/itisuniqueofficial/wi-fi-pass-crack.git
   cd wi-fi-pass-crack
   ```
2. **Install Python Dependencies**:
   ```bash
   pip install pywifi tqdm asyncio aiofiles psutil numpy scapy
   ```
3. **Install Npcap (Windows)**:
   - Download and install from [Npcap official site](https://nmap.org/npcap/).
4. **Optional: Install hashcat**:
   - Download from [hashcat.net](https://hashcat.net/) and add to your PATH.
5. **Verify Adapter Compatibility**:
   - Ensure your Wi-Fi adapter supports monitor mode (test with `scapy` or `airmon-ng`).

---

## How to Use
### Interactive Mode
Run the script without arguments for an interactive experience:
```bash
python wi-fi-pass-crack.py
```
#### Steps:
1. View available networks sorted by signal strength.
2. Enter the network number to target.
3. Provide an optional password file or press Enter for AI generation.
4. Enter custom words (e.g., "home,john") or skip.
5. Specify the number of passwords to generate (default: 5000).

### Command-Line Mode
Use CLI options for automation and precision:
```bash
python wi-fi-pass-crack.py --ssid "MyHomeWiFi" --password-file passwords.txt --custom-words "home,john" --num-passwords 10000 --adapters 2 --target-mac "00:11:22:33:44:55"
```

#### Options:
- `--ssid`: Target network name.
- `--password-file`: Path to a custom password list.
- `--custom-words`: Comma-separated keywords for password generation.
- `--num-passwords`: Number of AI-generated passwords.
- `--adapters`: Number of Wi-Fi adapters to use.
- `--target-mac`: MAC address of a specific device to deauth.

---

## Legal Disclaimer
This tool is for educational purposes only. Unauthorized use on networks you do not own or have explicit permission to test is illegal and unethical. The developer ([Your Name or Alias]) and contributors are not responsible for any misuse or illegal activities conducted with this tool. Always obtain consent before testing any network.

---

## Contributing
Contributions are welcome! Fork the repository, make improvements, and submit a pull request. Areas for enhancement:
- Full RNN integration with TensorFlow.
- GUI development.
- Cross-platform MAC spoofing support.

---

## Official Details
- **Version**: 1.0 (as of February 26, 2025)
- **License**: MIT License (see LICENSE file)
- **Repository**: [github.com/itisuniqueofficial/wi-fi-pass-crack](https://github.com/itisuniqueofficial/wi-fi-pass-crack)
- **Status**: Active development for educational purposes

---

## Credits
- **Developer**: It Is Unique Official
- **Inspiration**: xAI’s mission to accelerate human scientific discovery
- **Tools**: Built upon pywifi, scapy, and hashcat communities

Thank you for exploring `wi-fi-pass-crack`! Use it responsibly to learn and enhance your cybersecurity knowledge.
