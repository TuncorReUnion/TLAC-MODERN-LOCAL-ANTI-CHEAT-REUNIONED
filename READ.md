3. Run the installation script
cd TLAC-v0.1.0-x86_64-linux
chmod +x install.sh
sudo ./install.sh

⚠️ Notes
This project is developed for educational and open-source purposes. As a user-land tool, it requires root privileges to function properly.

4. Usage
TLAC requires the PID of the target process to monitor:
sudo TLAC <PID>

Example:
# Scan process with PID 1234:
sudo ac-server
sudo Anti-Cheat 1234
