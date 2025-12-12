# Active Directory and Splunk Demonstration

## Objective


The point of this project is to demonstrate a basic Active Directory Domain Services configuration, how to install Splunk on an Ubuntu CLI-based server, set up Splunk Universal Forwarder on domain computers, attempt RDP brute-forcing with THC-Hydra, and use Atomic Red Team to demonstrate testing capabilities. After using THC-Hydra and Atomic Red Team, we will view and analyze the generated telemetry in the Splunk web portal.

### Skills Learned


- Furthered knowledge of networking concepts 
- Advanced understanding of SIEM concepts and practical application (Installing Splunk, Universal Forwarder, and Index creation)
- Working in virtual environments (Oracle VirtualBox)
- Ability to configure Active Directory, set up domain services, create organizational units with users, and join machines to the domain
- Generating telemetry to analyze in SIEM (Splunk)
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of PowerShell and Linux terminal environment
- Troubleshooting methodology
- Development of critical thinking and problem-solving skills in cybersecurity.

### Languages and Utilities Used


- Splunk
- Sysmon
- THC-Hydra
- Atomic Red Team
- Oracle VirtualBox
- Active Directory
- PowerShell


### Environments


- Windows Server 2022
- Windows 10 Pro (22H2)
- Kali Linux 2025.3
- Ubuntu Server 24.04.3 LTS

## Steps
<img width="543" height="566" alt="usethis" src="https://github.com/user-attachments/assets/e943d7dc-0888-4438-82c0-8b1292196a07" />

*Ref 1: Network Diagram*

Create Windows 10 Pro VM in virtualbox using windows 10 ISO image file.

Create Kali Linux VM using pre-built VM from Kali.org (kali, kali)

Install Windows Server 2022 ISO (Password1)

Create Splunk server using Ubuntu Server 24.04.3 LTS (demo_user, Password1)

<img width="826" height="191" alt="Screenshot 2025-12-05 071338" src="https://github.com/user-attachments/assets/229f9e68-7942-47f8-999c-fe4da4463450" />

*Ref 2: Upon initial login run 'sudo apt-get update && sudo apt-get upgrade -y' to update and upgrade all of our repositories (Ubuntu)*

### Ubuntu Splunk Setup:

<img width="558" height="399" alt="Screenshot 2025-12-05 072707" src="https://github.com/user-attachments/assets/9ac19599-ebbf-4a2f-862a-903194b2e110" />

*Ref 3: In VirtualBox create NAT Network (192.168.10.0/24) and change the network settings on each virtual machine*

Set static IP addresses based on network diagram (192.168.10.10)

<img width="781" height="530" alt="Screenshot 2025-12-05 073743" src="https://github.com/user-attachments/assets/d7e31780-1ca7-4441-919c-84006fdb6ee0" />

*Ref 4: Use netplan in Ubuntu*

Apply netplan and verify configuration

<img width="965" height="510" alt="Screenshot 2025-12-05 074707" src="https://github.com/user-attachments/assets/5361c615-ccc3-4472-9a8b-da8377de7576" />

*Ref 5: Verify IP Config*

Download Splunk Enterprise for Linux

<img width="954" height="201" alt="Screenshot 2025-12-05 093123" src="https://github.com/user-attachments/assets/c4625aa9-9205-4659-8a34-323766dea7ef" />

*Ref 6: Install VirtualBox guest installations to enable shared folders and utilities*

In Ubuntu run 'sudo apt-get install virtualbox-guest-additions-iso' to enable shared folder with virtualbox

Also run 'sudo apt-get install virtualbox-guest-utils'

<img width="979" height="626" alt="Screenshot 2025-12-05 093713" src="https://github.com/user-attachments/assets/a69f9e0c-789d-4596-87c1-94ac9867ff9c" />

*Ref:7 Add Splunk installer via shared folder*

Reboot Ubuntu via 'sudo reboot'

<img width="468" height="98" alt="Screenshot 2025-12-05 094747" src="https://github.com/user-attachments/assets/b745cbed-8423-46fc-8cb6-712211372a33" />

*Ref: 8 Add user to vboxsf 'sudo adduser demo_user vboxsf'*

<img width="312" height="91" alt="Screenshot 2025-12-05 095230" src="https://github.com/user-attachments/assets/c6158c94-f4ba-413f-a2f4-98cbe65a4dee" />

*Ref: 9 Create new directory named "share" to mount Splunk shared folder to via 'mkdir share'*

<img width="710" height="61" alt="Screenshot 2025-12-05 095652" src="https://github.com/user-attachments/assets/c0fa1d22-a7e0-4272-9003-c8a4bffead10" />

*Ref: 10 Mount shared folder onto "share" directory with 'sudo mount -t vboxsf -o uid=1000,gid=1000 splunk_installer share/'*

<img width="827" height="127" alt="Screenshot 2025-12-05 100105" src="https://github.com/user-attachments/assets/1ecf3099-b315-40f4-9aa6-a4c9c7b216ea" />

*Ref: 11 Install Splunk via 'sudo dpkg -i splunk-10.0.2-e2d18b4767e9-linux-amd64.deb' (Using shared folder through VirtualBox)*

<img width="789" height="332" alt="Screenshot 2025-12-05 101625" src="https://github.com/user-attachments/assets/c2e77d36-2800-4654-8e39-480beb6212f5" />

*Ref: 12 Change to Splunk directory location 'cd /opt/splunk'*

Notice both owner and group are "splunk"

Change to user "splunk" via 'sudo -u splunk bash'

<img width="314" height="50" alt="Screenshot 2025-12-05 102103" src="https://github.com/user-attachments/assets/be8e72c6-97a4-4f0a-848e-f8b4588259c8" />

*Ref: 13 Change to to /bin directory 'cd bin' to access binaries splunk can use*

Run './splunk start' to install Splunk

Read and accept license agreement

Create administrative username and password (demo_user, Password1)

<img width="650" height="101" alt="Screenshot 2025-12-05 102922" src="https://github.com/user-attachments/assets/ef38a95b-be8a-40ef-bf24-0f903295b8e6" />

*Ref 14: Exit splunk user 'exit', change into bin directory, run 'sudo ./splunk enable boot-start -user splunk' to ensure splunk runs anytime the vm reboots as the user "splunk"*

### Install sysmon and Splunk Universal Forwarder on Target (Windows 10 Pro) and ADDC server (Windows Server 2022):

<img width="808" height="608" alt="Screenshot 2025-12-05 103911" src="https://github.com/user-attachments/assets/704eaade-bd92-43a3-adfe-ea7cc298d62b" />

*Ref 15: For ease of identification rename the target Windows machine "target-pc"*

<img width="781" height="553" alt="Screenshot 2025-12-05 104606" src="https://github.com/user-attachments/assets/4bea532e-2b0b-4623-bd3e-feaf086a93d4" />

*Ref 16: Statically assign IPv4 network adapter settings based on network diagram (192.168.10.100)*

Next, download the Splunk Universal Forwarder via the browser by going to the Splunk website

<img width="623" height="61" alt="Screenshot 2025-12-05 105840" src="https://github.com/user-attachments/assets/1e903998-d7eb-4544-8745-1b313a3e04b2" />

*Ref 17: After downloading, run the .msi to access the setup wizard*

Going through the setup wizard we set the username to demo_user for ease of the lab with the same password "Password1"

<img width="779" height="548" alt="Screenshot 2025-12-05 110444" src="https://github.com/user-attachments/assets/ec139f08-5105-4a23-b9fe-67b005d54e2a" />

*Ref 18: Leave Deployment Server blank and set Receiving Indexer to the IP of the Splunk server (192.168.10.10) with default port 9997*

Next, download Sysmon from Microsoft

<img width="1007" height="643" alt="Screenshot 2025-12-07 103413" src="https://github.com/user-attachments/assets/bf69470d-f730-47f0-926c-e3687672d4d1" />

*Ref 19: To configure Sysmon download the configuration file by Olaf*

Running PowerShell as administrator change directory to the extracted Sysmon location

<img width="816" height="567" alt="Screenshot 2025-12-07 104558" src="https://github.com/user-attachments/assets/f355e11e-da60-459a-8710-121f6ef91c29" />

*Ref 20: Next run '.\Sysmon64.exe -i ..\sysmonconfig.xml' to install sysmon with the configuration file*

<img width="540" height="352" alt="Screenshot 2025-12-07 110707" src="https://github.com/user-attachments/assets/729891aa-ea07-4eea-b3d6-9cbecc2ccbeb" />

*Ref 21: To configure the Splunk forwarder on what to send to Splunk server, running Notepad as administrator, create an input configuration file instructing the forwarder to send Application, System, Security, and Sysmon events*

<img width="739" height="540" alt="Screenshot 2025-12-07 110816" src="https://github.com/user-attachments/assets/cf743f8e-ad6d-420d-8b31-6448f4a02be2" />

*Ref 22: Save the file to \SplunkUniversalForwarder\etc\system\local as "inputs.conf"*

<img width="516" height="527" alt="Screenshot 2025-12-07 111325" src="https://github.com/user-attachments/assets/be60c987-3041-434f-8ae7-f960db191c73" />

*Ref 23: Using the Services app, change to log on as local system account to allow log collection permissions*

Restart Splunk Universal Forwarder service

<img width="993" height="636" alt="Screenshot 2025-12-07 111925" src="https://github.com/user-attachments/assets/eb1fcedf-4f30-4600-bd18-bf61cc5e4311" />

*Ref 24: In the Splunk web portal create a new index named "endpoint"*

<img width="1000" height="344" alt="Screenshot 2025-12-07 112316" src="https://github.com/user-attachments/assets/154fdeff-96b5-48a0-a351-4b8b3a86d27f" />

*Ref 25: Under Settings^Forwarding and Receiving, hit configure receiving and configure it to listen on default port 9997*

Repeat steps^ for Active Directory machine

### Install and configure Active Directory, Promote to Domain Controller, Join Target(Windows 10 Pro) to the domain:

<img width="488" height="282" alt="Screenshot 2025-12-08 071018" src="https://github.com/user-attachments/assets/05c7d01b-62b4-4f41-abf2-1c19e27fa1d1" />

*Ref 26: In server manager go to Add Roles and Features*

<img width="702" height="458" alt="Screenshot 2025-12-08 071228" src="https://github.com/user-attachments/assets/c2f7dece-b6c8-488c-bc31-520c6a2556df" />

*Ref 27: Click next until you reach Server Roles then select Active Directory Domain Services*

Click next until install

<img width="411" height="294" alt="Screenshot 2025-12-08 073123" src="https://github.com/user-attachments/assets/b866acbb-dedb-406d-8d01-70b029fad1df" />

*Ref 28: In the server manager notifications click promote this server to a domain controller*

<img width="597" height="442" alt="Screenshot 2025-12-08 073330" src="https://github.com/user-attachments/assets/6c7dfaff-3802-463a-8cc9-710f9de1a2b4" />

*Ref 29: Select add new forest and name the domain including a top level domain, in this case .local*

Leave default settings and create a password (Password1)

<img width="550" height="295" alt="Screenshot 2025-12-08 073850" src="https://github.com/user-attachments/assets/6f85d1aa-aaab-4428-bb9c-11a521f0f928" />

*Ref 30: Click through the default settings until install*

The server will automatically restart

<img width="455" height="329" alt="Screenshot 2025-12-08 075205" src="https://github.com/user-attachments/assets/25be938b-46d2-48fc-9e5a-b18b1c6f9793" />

*Ref 31: Under tools select active directory users and computers*

To simulate a real world environment with organizational units, right click domain and select organizational unit naming it "IT"

<img width="484" height="424" alt="Screenshot 2025-12-08 082737" src="https://github.com/user-attachments/assets/f4c1e079-44db-4bef-b171-93d2b33f2366" />

*Ref 32: Create a new user within the OU. For this example, we will name it "Jenny Smith", username:jsmit*

Disable change password at next logon for the lab environment ease of use

<img width="808" height="549" alt="Screenshot 2025-12-08 083029" src="https://github.com/user-attachments/assets/9dfcf015-ee05-42b6-a31d-37a9a5a20141" />

*Ref 33: For practice, create another OU named HR and add a new user*

<img width="841" height="570" alt="Screenshot 2025-12-08 224909" src="https://github.com/user-attachments/assets/48e646f4-16bd-4097-997d-80627b2d4215" />

*Ref 34: Join the Windows 10 PC to the domain by going to advanced system settings under this pc and change domain*

<img width="499" height="520" alt="Screenshot 2025-12-08 225336" src="https://github.com/user-attachments/assets/4f3b0596-6f02-4bfe-9228-c95fd80c84e6" />

*Ref 35: Our Windows 10 machine will throw an error because it does not know how to resolve our domain. To fix this, go to IPv4 adapter settings and change the DNS server IP address to the domain controller*

<img width="666" height="417" alt="Screenshot 2025-12-08 225517" src="https://github.com/user-attachments/assets/efb4b3c8-f950-4575-88b3-dd4a791a9cf9" />

*Ref 36: Verify configuration with command prompt ipconfig /all*

<img width="857" height="580" alt="Screenshot 2025-12-09 071133" src="https://github.com/user-attachments/assets/c8a1bc38-0117-48a1-a6fd-8401f0ee7b7a" />

*Ref 37: With the error resolved, join the domain again using the administrator account and password because this account has permission to join machines to the domain*

Restart the machine to apply changes

<img width="519" height="362" alt="Screenshot 2025-12-09 072028" src="https://github.com/user-attachments/assets/91c23d50-01f2-40ab-b3b4-b73035b58798" />

*Ref 38: Hitting "Other user" log in with previously created user "jsmith"*

We have now successfully set up the Active Directory server with two sample users.

We have also installed Splunk on an Ubuntu server, Splunk Universal Forwarders on the Windows based machines, and Sysmon to enhance logging capability

### Use Kali Linux to perform brute force attack on domain users, view telemetry generated in Splunk:

In the Kali machine select the ethernet icon and select edit connections

<img width="721" height="564" alt="Screenshot 2025-12-09 082345" src="https://github.com/user-attachments/assets/ad8805b3-ab74-47fa-8328-db228becb7a2" />

*Ref 39: In the settings for wired connection 1, select manual configuration under IPv4 and add the static configuration per diagram specifications (192.168.10.250)*

<img width="242" height="153" alt="Screenshot 2025-12-09 082529" src="https://github.com/user-attachments/assets/54c9bf56-b0f0-4835-ba3e-30b821f0f2e2" />

*Ref 40: To implement changes, under the ethernet icon, disconnect and reconnect wired connection 1*

<img width="451" height="89" alt="Screenshot 2025-12-09 083743" src="https://github.com/user-attachments/assets/b0a526a7-0107-455d-9032-43892fd699c2" />

*Ref 41: To ensure software repositories are up to date run 'sudo apt-get update && sudo apt-get upgrade -y'*

<img width="354" height="205" alt="Screenshot 2025-12-09 084643" src="https://github.com/user-attachments/assets/5ce59adc-1004-4cc7-b1a0-98ed407a814a" />

*Ref 42: Create a new directory named "ad-project" by running 'mkdir ad-project'*

<img width="361" height="107" alt="Screenshot 2025-12-09 085133" src="https://github.com/user-attachments/assets/072e3c79-d863-4631-ab98-237aa151aa74" />

*Ref 43: Install hydra by running 'sudo apt-get install -y hydra'*

This a brute force tool used to brute force popular services, in this case Windows Remote Desktop Protocol RDP

Access a pre installed wordlist on Kali by changing directory with 'cd /usr/share/wordlists/'

<img width="545" height="260" alt="Screenshot 2025-12-09 085855" src="https://github.com/user-attachments/assets/3877a709-a154-4aae-ae8b-a8d4b1e17251" />

*Ref 44: Unzip the wordlist file using 'sudo gunzip rockyou.txt.gz'*

Copy this file to ad-project with 'cp rockyou.txt ~/Desktop/ad-project/'

Change to the ad-project directory to access the wordlist with 'cd ~/Desktop/ad-project/'

<img width="402" height="235" alt="Screenshot 2025-12-09 091037" src="https://github.com/user-attachments/assets/9c0fdd28-2b6d-43f9-8576-0c98b4da8959" />

*Ref 45: We will only use the first 20 lines of the file for this demonstration so output the first 20 lines to a new file with 'head -n 20 rockyou.txt > passwords.txt'*

<img width="635" height="382" alt="Screenshot 2025-12-09 095113" src="https://github.com/user-attachments/assets/cf849461-2381-4f39-8aec-de0a6e807675" />

*Ref 46: In addition to the 20 passwords, for demonstration purposes, we will add the password for user jsmith at the bottom of the list with 'nano passwords.txt' and add "Password1"*

<img width="442" height="480" alt="Screenshot 2025-12-09 095509" src="https://github.com/user-attachments/assets/8d55d1c3-2350-4d99-a79f-3be62dcbbd9a" /> <img width="539" height="349" alt="Screenshot 2025-12-09 095727" src="https://github.com/user-attachments/assets/06230464-8043-49fc-b024-698113e4ab6c" />

*Ref 47: Enable RDP on the Windows 10 target machine under This PC^Properties^Advanced system settings, hit allow remote connections and specify previously created users "jsmith" and "tsmith"*

<img width="640" height="449" alt="Screenshot 2025-12-11 073213" src="https://github.com/user-attachments/assets/4004dc96-b138-4fbd-ba6f-0f45a6b9d8bf" />

*Ref 48: Now on the Kali machine use hydra by running 'hydra -l jsmith -P passwords.txt 192.168.10.100 rdp'*

<img width="523" height="553" alt="Screenshot 2025-12-11 074915" src="https://github.com/user-attachments/assets/6e1f0c3b-3e85-4d34-80f6-85c0bdd8298e" />

*Ref 49: In Splunk we can filter using event code 4625 to see the login attempts by hydra*

Notice how all of the events happen around the same time. This can be an indicator of brute force activity

<img width="96" height="88" alt="Screenshot 2025-12-11 075437" src="https://github.com/user-attachments/assets/def1043d-7045-4129-8113-0f613d0ef265" /> <img width="403" height="127" alt="Screenshot 2025-12-11 075658" src="https://github.com/user-attachments/assets/d5197092-3a49-419d-ad3a-280eeca605f5" />

*Ref 50: Notice the presence of event code 4624, this indicates a successful logon*

Within the event details we can see the source of the logon as 192.168.10.250 which is our Kali machine

### Setup Atomic Red Team on the target, Windows 10 Pro machine:

<img width="844" height="215" alt="Screenshot 2025-12-11 085757" src="https://github.com/user-attachments/assets/812771fe-9fe2-44c9-bb24-736e9641cd5a" />

*Ref 51: To prepare the machine for Atomic Red Team in administrative PowerShell run 'Set-ExecutionPolicy Bypass CurrentUser'*

<img width="797" height="619" alt="Screenshot 2025-12-11 090104" src="https://github.com/user-attachments/assets/773131ed-36b0-4380-9ff2-2466f76bfa04" /> <img width="293" height="176" alt="Screenshot 2025-12-11 090240" src="https://github.com/user-attachments/assets/03d033ff-c126-42ad-97f1-ba4e0be262cd" />

*Ref 52: Now we will set an exclusion for the C drive to prevent Microsoft Defender from detecting and removing files from Atomic Red Team*

Under Virus and threat protection settings hit "Add or remove exclusions"

Select the C drive as a folder

<img width="772" height="298" alt="Screenshot 2025-12-11 092724" src="https://github.com/user-attachments/assets/f5f6da67-0bc8-4a3c-8b5b-96b1c913a1e7" />

*Ref 53: To install Atomic Red Team run 'IEX (IWR  -UseBasicParsing); Install-AtomicRedTeam -getAtomics', use 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' for the Uri paremeter*

Under the AtomicRedTeam directory notice the folder named Atomics

This holds technique ID's based on the MITRE ATT&CK framework

<img width="1851" height="782" alt="Screenshot 2025-12-11 100528" src="https://github.com/user-attachments/assets/eaf4b146-27aa-4881-8178-003b404344e4" /> <img width="626" height="393" alt="Screenshot 2025-12-11 100635" src="https://github.com/user-attachments/assets/6cf6bcb5-d1df-4156-86bf-6abc67ecddd2" />

*Ref 54: You can learn about each technique via MITRE's Att&ck Matrix for Enterprise*

You may need to import the Invoke-AtomicTest module with 'Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force'

<img width="768" height="318" alt="Screenshot 2025-12-11 101552" src="https://github.com/user-attachments/assets/e5a41a8d-0a28-4e65-b11b-865ac4ce2573" />

*Ref 55: For example we can Invoke T1136.001 with 'Invoke-AtomicTest T1136.001'*

Notice that the script created a new user named "NewLocalUser"

<img width="1009" height="548" alt="Screenshot 2025-12-11 102439" src="https://github.com/user-attachments/assets/67940535-b3bd-422c-abdf-c6286de4dfd0" />

*Ref 56: If we check Splunk we can view that generated telemetry relating to account creation*

We can also see event code 4720 which relates to account creation

Since this event is detectable, it is possible to build alerts for this activity in the future

















