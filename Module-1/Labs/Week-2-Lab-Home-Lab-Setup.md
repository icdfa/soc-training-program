# Week 2 Lab: Building Your SOC Home Lab

## Learning Outcomes

By the end of this lab, you will be able to:

- Set up a complete virtual SOC lab environment using VirtualBox or VMware
- Configure virtual networking for security monitoring
- Deploy and configure pfSense as a firewall
- Install and configure a basic Splunk instance
- Set up virtual machines for attack simulation
- Document your lab architecture

## Objective

Build a complete, functional SOC home lab that you will use throughout this training program. This lab will include a firewall, SIEM, attacker machine, and victim machines.

## Prerequisites

- A host computer with:
  - **CPU:** Intel Core i5/AMD Ryzen 5 or better (with virtualization support)
  - **RAM:** Minimum 16GB (32GB recommended)
  - **Storage:** 200GB free space (SSD recommended)
  - **OS:** Windows 10/11, macOS, or Linux
- Virtualization enabled in BIOS/UEFI
- Administrative access to your computer

## Lab Duration

Approximately 3-4 hours (plus download time)

---

## Part 1: Hypervisor Installation (30 minutes)

### Step 1: Choose Your Hypervisor

You will need a Type 2 hypervisor (runs on top of your host OS). Choose one:

**Option A: VirtualBox (Recommended for beginners)**
- **Pros:** Free, open-source, cross-platform, easy to use
- **Cons:** Slightly slower performance
- **Download:** https://www.virtualbox.org/wiki/Downloads

**Option B: VMware Workstation Player/Fusion**
- **Pros:** Better performance, more features
- **Cons:** Free for personal use only
- **Download:** 
  - Windows/Linux: https://www.vmware.com/products/workstation-player.html
  - macOS: https://www.vmware.com/products/fusion.html

**For this guide, we'll use VirtualBox, but the concepts apply to VMware as well.**

### Step 2: Install VirtualBox

1. **Download VirtualBox:**
   - Go to https://www.virtualbox.org/wiki/Downloads
   - Download the version for your host OS
   - Also download the **VirtualBox Extension Pack**

2. **Install VirtualBox:**
   
   **Windows:**
   ```
   - Run the installer (VirtualBox-x.x.xx-xxxxxx-Win.exe)
   - Click "Next" through the wizard
   - Accept the default installation location
   - Click "Yes" when prompted about network interfaces
   - Click "Install"
   - Click "Finish"
   ```

   **macOS:**
   ```
   - Open the .dmg file
   - Double-click VirtualBox.pkg
   - Follow the installation wizard
   - Allow the system extension when prompted
   - Enter your password when requested
   ```

   **Linux (Ubuntu/Debian):**
   ```bash
   sudo apt update
   sudo apt install virtualbox virtualbox-ext-pack
   ```

3. **Install Extension Pack:**
   - Open VirtualBox
   - Go to **File → Preferences → Extensions**
   - Click the **+** icon
   - Select the downloaded Extension Pack file
   - Click "Install" and accept the license

4. **Verify Installation:**
   - Open VirtualBox
   - Go to **Help → About VirtualBox**
   - Verify the version number

### Step 3: Enable Virtualization in BIOS

If you haven't already enabled virtualization:

1. **Restart your computer**
2. **Enter BIOS/UEFI** (usually F2, F10, F12, or Del during boot)
3. **Find virtualization settings:**
   - Intel: Look for "Intel VT-x" or "Intel Virtualization Technology"
   - AMD: Look for "AMD-V" or "SVM Mode"
4. **Enable the setting**
5. **Save and exit BIOS**

---

## Part 2: Network Design and Configuration (45 minutes)

### Step 4: Plan Your Lab Network

Your SOC lab will have the following network architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                        Host Computer                         │
│  ┌───────────────────────────────────────────────────────┐  │
│  │              VirtualBox Host-Only Network              │  │
│  │                    192.168.56.0/24                     │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐│  │
│  │  │ pfSense  │  │  Splunk  │  │  Kali    │  │Windows ││  │
│  │  │ Firewall │  │   SIEM   │  │ Attacker │  │ Victim ││  │
│  │  │ .56.1    │  │  .56.10  │  │  .56.20  │  │ .56.30 ││  │
│  │  └──────────┘  └──────────┘  └──────────┘  └────────┘│  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Network Segments:**
- **Management Network:** 192.168.56.0/24 (Host-Only)
- **Internet Access:** NAT (for updates and downloads)

### Step 5: Create Virtual Networks in VirtualBox

1. **Open VirtualBox**

2. **Create Host-Only Network:**
   - Go to **File → Host Network Manager** (or **Tools → Network**)
   - Click **Create**
   - Configure the adapter:
     - **Adapter:**
       - IPv4 Address: `192.168.56.1`
       - IPv4 Network Mask: `255.255.255.0`
     - **DHCP Server:**
       - Uncheck "Enable Server" (we'll use static IPs)
   - Click **Apply**

3. **Verify Network Creation:**
   - You should see `vboxnet0` (Linux/macOS) or `VirtualBox Host-Only Ethernet Adapter` (Windows)
   - Note the adapter name for later use

---

## Part 3: pfSense Firewall Setup (60 minutes)

### Step 6: Download pfSense

1. Go to https://www.pfsense.org/download/
2. Select:
   - **Architecture:** AMD64 (64-bit)
   - **Installer:** DVD Image (ISO) Installer
   - **Mirror:** Choose closest location
3. Download the ISO file (approximately 700MB)

### Step 7: Create pfSense VM

1. **In VirtualBox, click "New"**

2. **Configure VM Settings:**
   - **Name:** pfSense-Firewall
   - **Type:** BSD
   - **Version:** FreeBSD (64-bit)
   - Click **Next**

3. **Memory:**
   - Allocate **1024 MB (1GB)** RAM
   - Click **Next**

4. **Hard Disk:**
   - Select "Create a virtual hard disk now"
   - Click **Create**

5. **Hard Disk Type:**
   - Select **VDI (VirtualBox Disk Image)**
   - Click **Next**

6. **Storage:**
   - Select **Dynamically allocated**
   - Click **Next**

7. **Disk Size:**
   - Set to **8 GB**
   - Click **Create**

### Step 8: Configure pfSense VM Network

1. **Select the pfSense VM** and click **Settings**

2. **Go to Network:**
   
   **Adapter 1 (WAN - Internet):**
   - Enable Network Adapter: ✓
   - Attached to: **NAT**
   - Click **OK**

   **Adapter 2 (LAN - Internal):**
   - Click **Adapter 2** tab
   - Enable Network Adapter: ✓
   - Attached to: **Host-only Adapter**
   - Name: Select your host-only network (vboxnet0)
   - Click **OK**

### Step 9: Install pfSense

1. **Start the pfSense VM**

2. **Mount the ISO:**
   - Click **Devices → Optical Drives → Choose disk image**
   - Select the pfSense ISO file

3. **Boot from ISO:**
   - The VM will boot from the ISO
   - Wait for the pfSense installer to load

4. **Installation Steps:**

   **Accept Copyright:**
   - Press **Enter** to Accept

   **Install pfSense:**
   - Select **Install**
   - Press **Enter**

   **Keymap Selection:**
   - Select your keyboard layout (usually **US**)
   - Press **Enter**

   **Partitioning:**
   - Select **Auto (UFS)** for automatic partitioning
   - Press **Enter**

   **Installation Progress:**
   - Wait for the installation to complete (2-3 minutes)

   **Manual Configuration:**
   - Select **No** when asked for manual configuration
   - Press **Enter**

   **Reboot:**
   - Select **Reboot**
   - **Important:** Remove the ISO before reboot:
     - Click **Devices → Optical Drives → Remove disk from virtual drive**

### Step 10: Configure pfSense Interfaces

1. **After reboot, you'll see the pfSense console menu**

2. **Assign Interfaces:**
   - If prompted "Should VLANs be set up now?", type **n** and press Enter
   
   **WAN Interface:**
   - Enter **em0** (or the first interface shown)
   - Press **Enter**

   **LAN Interface:**
   - Enter **em1** (or the second interface shown)
   - Press **Enter**

   **Additional Interfaces:**
   - Press **Enter** (none)

   **Confirm:**
   - Type **y** and press **Enter**

3. **Set LAN IP Address:**
   - From the menu, select **2** (Set interface(s) IP address)
   - Select **2** (LAN)
   - Enter LAN IP: **192.168.56.1**
   - Enter subnet mask: **24**
   - Press **Enter** for no upstream gateway
   - Press **Enter** for no IPv6
   - Enable DHCP? Type **n** (we'll use static IPs)
   - Revert to HTTP as webConfigurator protocol? Type **n**

4. **Verify Configuration:**
   - You should see:
     - WAN: DHCP (from NAT)
     - LAN: 192.168.56.1

### Step 11: Access pfSense Web Interface

1. **From your host computer, open a web browser**

2. **Navigate to:** https://192.168.56.1

3. **Accept the security warning** (self-signed certificate)

4. **Login:**
   - Username: `admin`
   - Password: `pfsense`

5. **Setup Wizard:**
   - Click **Next**
   - Hostname: `pfsense`
   - Domain: `localdomain`
   - Click **Next**
   - Set your timezone
   - Click **Next**
   - Leave WAN configuration as DHCP
   - Click **Next**
   - Uncheck "Block RFC1918 Private Networks"
   - Click **Next**
   - **Change admin password** (important!)
   - Click **Next**
   - Click **Reload**
   - Click **Finish**

---

## Part 4: Splunk SIEM Setup (60 minutes)

### Step 12: Download Ubuntu Server

1. Go to https://ubuntu.com/download/server
2. Download **Ubuntu Server 22.04 LTS** ISO (approximately 2GB)

### Step 13: Create Splunk VM

1. **In VirtualBox, click "New"**

2. **Configure VM:**
   - **Name:** Splunk-SIEM
   - **Type:** Linux
   - **Version:** Ubuntu (64-bit)
   - **Memory:** 4096 MB (4GB) minimum, 8192 MB (8GB) recommended
   - **Hard Disk:** Create virtual hard disk, VDI, Dynamically allocated, **50 GB**

3. **Network Configuration:**
   - **Settings → Network → Adapter 1**
   - Attached to: **Host-only Adapter**
   - Name: Select your host-only network

### Step 14: Install Ubuntu Server

1. **Start the VM** and mount the Ubuntu ISO

2. **Installation Steps:**
   - Select language: **English**
   - Select **Install Ubuntu Server**
   - Language: **English**
   - Keyboard: Select your layout
   - Network: Accept DHCP (we'll set static later)
   - Proxy: Leave blank
   - Mirror: Accept default
   - Storage: **Use entire disk**
   - Confirm: **Continue**
   - Profile Setup:
     - Your name: `socadmin`
     - Server name: `splunk-siem`
     - Username: `socadmin`
     - Password: [Choose a strong password]
   - SSH: **Install OpenSSH server** (check the box)
   - Featured snaps: Don't select any
   - Wait for installation to complete
   - **Reboot**

3. **Login** with your credentials

### Step 15: Configure Static IP

1. **Check current IP:**
   ```bash
   ip addr show
   ```

2. **Edit netplan configuration:**
   ```bash
   sudo nano /etc/netplan/00-installer-config.yaml
   ```

3. **Replace contents with:**
   ```yaml
   network:
     version: 2
     ethernets:
       enp0s3:
         addresses:
           - 192.168.56.10/24
         nameservers:
           addresses:
             - 8.8.8.8
             - 8.8.4.4
         routes:
           - to: default
             via: 192.168.56.1
   ```

4. **Apply configuration:**
   ```bash
   sudo netplan apply
   ```

5. **Verify:**
   ```bash
   ip addr show enp0s3
   ping -c 3 8.8.8.8
   ```

### Step 16: Install Splunk

1. **Update system:**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Download Splunk:**
   ```bash
   cd /tmp
   wget -O splunk.tgz 'https://download.splunk.com/products/splunk/releases/9.1.2/linux/splunk-9.1.2-b6b9c8185839-Linux-x86_64.tgz'
   ```

3. **Extract Splunk:**
   ```bash
   sudo tar -xvzf splunk.tgz -C /opt
   ```

4. **Start Splunk:**
   ```bash
   sudo /opt/splunk/bin/splunk start --accept-license
   ```

5. **Create admin credentials:**
   - Username: `admin`
   - Password: [Choose a strong password]

6. **Enable boot start:**
   ```bash
   sudo /opt/splunk/bin/splunk enable boot-start -user socadmin
   ```

7. **Access Splunk:**
   - From your host browser: http://192.168.56.10:8000
   - Login with admin credentials

---

## Part 5: Attack and Victim Machines (45 minutes)

### Step 17: Create Kali Linux (Attacker) VM

1. **Download Kali Linux:**
   - Go to https://www.kali.org/get-kali/
   - Download **Kali Linux 64-bit (Installer)**

2. **Create VM:**
   - Name: Kali-Attacker
   - Type: Linux
   - Version: Debian (64-bit)
   - Memory: 2048 MB
   - Hard Disk: 40 GB

3. **Network:**
   - Adapter 1: Host-only Adapter

4. **Install Kali:**
   - Start VM and mount Kali ISO
   - Select **Graphical Install**
   - Follow installation wizard
   - Set static IP: **192.168.56.20**

### Step 18: Create Windows 10 (Victim) VM

1. **Download Windows 10:**
   - Go to https://www.microsoft.com/software-download/windows10
   - Download Windows 10 ISO

2. **Create VM:**
   - Name: Windows10-Victim
   - Type: Microsoft Windows
   - Version: Windows 10 (64-bit)
   - Memory: 4096 MB
   - Hard Disk: 50 GB

3. **Network:**
   - Adapter 1: Host-only Adapter

4. **Install Windows:**
   - Start VM and mount Windows ISO
   - Follow installation wizard
   - Skip product key (evaluation mode)
   - Set static IP: **192.168.56.30**

---

## Part 6: Lab Verification and Documentation (30 minutes)

### Step 19: Test Connectivity

1. **From each VM, ping others:**
   ```bash
   ping 192.168.56.1   # pfSense
   ping 192.168.56.10  # Splunk
   ping 192.168.56.20  # Kali
   ping 192.168.56.30  # Windows
   ping 8.8.8.8        # Internet
   ```

2. **Verify web access:**
   - pfSense: https://192.168.56.1
   - Splunk: http://192.168.56.10:8000

### Step 20: Create Network Diagram

Create a network diagram documenting your lab. Use draw.io or similar tool.

**Include:**
- All VMs with IP addresses
- Network connections
- VM specifications (CPU, RAM, Disk)
- Software versions

### Step 21: Take VM Snapshots

**Important:** Take snapshots of all VMs in their clean state!

1. **For each VM:**
   - Shut down the VM
   - Right-click → Snapshots → Take
   - Name: "Clean Install - [Date]"
   - Description: "Fresh installation, ready for labs"

---

## Deliverables

Submit the following:

1. **Network Diagram** (PNG or PDF)
   - Show all VMs and their connections
   - Include IP addresses and specifications

2. **Screenshots:**
   - pfSense dashboard
   - Splunk login page
   - Kali Linux desktop
   - Windows 10 desktop
   - Successful ping tests from each VM

3. **Lab Documentation** (Markdown or PDF):
   - List of all VMs with specifications
   - IP address assignments
   - Admin credentials (store securely!)
   - Any issues encountered and how you resolved them

4. **Verification Checklist:**
   - [ ] VirtualBox installed and working
   - [ ] Host-only network created (192.168.56.0/24)
   - [ ] pfSense installed and accessible
   - [ ] Splunk installed and accessible
   - [ ] Kali Linux installed
   - [ ] Windows 10 installed
   - [ ] All VMs can ping each other
   - [ ] All VMs can access the internet
   - [ ] Snapshots taken of all VMs

---

## Troubleshooting

### Issue: VMs can't ping each other

**Solution:**
- Verify all VMs are on the same host-only network
- Check firewall settings on each VM
- Verify static IP configurations

### Issue: No internet access from VMs

**Solution:**
- Verify pfSense WAN interface has an IP
- Check pfSense firewall rules (allow LAN to any)
- Verify DNS settings (8.8.8.8)

### Issue: Can't access pfSense/Splunk web interface

**Solution:**
- Verify VMs are running
- Check IP addresses with `ip addr` (Linux) or `ipconfig` (Windows)
- Try accessing from the VM itself first
- Disable host firewall temporarily to test

### Issue: VirtualBox won't start VMs (VT-x error)

**Solution:**
- Enable virtualization in BIOS
- On Windows, disable Hyper-V: `bcdedit /set hypervisorlaunchtype off`
- Restart your computer

---

## Next Steps

Congratulations! You now have a complete SOC lab environment. In the next labs, you will:

- Configure log forwarding to Splunk
- Set up Security Onion for network monitoring
- Deploy Wazuh for endpoint detection
- Simulate attacks and practice detection

**Important:** Keep your lab VMs updated and take regular snapshots before each lab!

---

## Additional Resources

- [VirtualBox Documentation](https://www.virtualbox.org/manual/)
- [pfSense Documentation](https://docs.netgate.com/pfsense/en/latest/)
- [Splunk Documentation](https://docs.splunk.com/)
- [Building a SOC Lab - YouTube Playlist](https://www.youtube.com/results?search_query=building+soc+lab)

---

**Lab Completion Time:** [Record your time]  
**Difficulty Level:** Beginner  
**Estimated Cost:** $0 (all free/open-source software)
