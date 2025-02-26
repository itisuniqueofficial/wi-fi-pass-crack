Here are all the **command-line options** mentioned in the COMMANDS.md for the `wi-fi-pass-crack` tool:  

---

### **1. Basic Usage (Interactive Mode)**  
Run without arguments to launch the interactive menu:  
```bash
python wi-fi-pass-crack.py
```
- This will:
  - Scan for available Wi-Fi networks.
  - Let you choose a target network.
  - Ask for a password list or generate passwords using AI.
  - Start capturing the handshake and attempt cracking.  

---

### **2. Command-Line Mode (Automated Execution)**  
You can use command-line arguments for precise control:  
```bash
python wi-fi-pass-crack.py --ssid "MyHomeWiFi" --password-file passwords.txt --custom-words "home,john" --num-passwords 10000 --adapters 2 --target-mac "00:11:22:33:44:55"
```
#### **Command-Line Arguments:**
| Option             | Description |
|--------------------|-------------|
| `--ssid "NetworkName"` | Specifies the target Wi-Fi network (SSID). |
| `--password-file passwords.txt` | Uses a custom password list for cracking. |
| `--custom-words "home,john"` | Adds custom words to AI password generation. |
| `--num-passwords 10000` | Defines the number of AI-generated passwords. |
| `--adapters 2` | Uses multiple Wi-Fi adapters for faster scanning/cracking. |
| `--target-mac "00:11:22:33:44:55"` | Sends deauth packets to a specific device (optional). |

---

### **3. Examples of Command Usage**
#### **Capture Handshake & Crack Wi-Fi Using AI Passwords**
```bash
python wi-fi-pass-crack.py --ssid "OfficeWiFi" --num-passwords 5000
```
- This will:
  - Scan for a network named `"OfficeWiFi"`.  
  - Capture the WPA/WPA2 handshake.  
  - Generate **5,000 AI-based passwords** and attempt cracking.  

#### **Use a Custom Wordlist Instead of AI Passwords**
```bash
python wi-fi-pass-crack.py --ssid "GuestWiFi" --password-file rockyou.txt
```
- Uses the `rockyou.txt` password list instead of AI-generated passwords.  

#### **Deauthenticate a Specific Device**
```bash
python wi-fi-pass-crack.py --ssid "MyHomeWiFi" --target-mac "00:11:22:33:44:55"
```
- Forces the device with MAC **00:11:22:33:44:55** to disconnect from the network.  

#### **Use Multiple Wi-Fi Adapters for Parallel Attacks**
```bash
python wi-fi-pass-crack.py --ssid "PublicWiFi" --adapters 3
```
- Uses **3 Wi-Fi adapters** for faster handshake capture and cracking.  

---

### **4. File Outputs**
After execution, the tool may generate these files:
- **`handshake_<SSID>.cap`** → Captured WPA/WPA2 handshake.
- **`cracked_networks.json`** → Stores cracked passwords.
- **`wi-fi-pass-crack.log`** → Detailed logs for debugging.
- **`captured_passwords.txt`** → Stores successful password attempts.  

---

### **⚠️ Legal Disclaimer**
This tool is for **educational purposes only**. Unauthorized use on networks **you do not own or have permission to test** is **illegal and unethical**.  

Let me know if you need further explanations!
