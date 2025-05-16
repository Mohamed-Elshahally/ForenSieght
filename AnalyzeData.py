import pandas as pd
import os
from IPcheck import check_ip_reputation
from filehashcheck import scan_hash_and_decide
from geminifw import check_message
#from geminiPower import check_powerShell
from geministartup import check_Startup
from gemini import check_content
from geminiapp import check_content2
from geminisys import check_content3
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from datetime import datetime
import hashlib
import re
import base64
import logging
import pefile
import ipaddress
import threading


API_KEYS = ["list of APIS"]

Gemini_Key = ["list of APIS"]

INPUT_DIR = "C:\\InvestigationData"

def read_csv(file):
    """Safely read a CSV file, returning an empty DataFrame if it fails."""
    file_path = os.path.join(INPUT_DIR, file)
    try:
        return pd.read_csv(file_path) if os.path.exists(file_path) else pd.DataFrame()
    except (pd.errors.EmptyDataError, Exception) as e:
        print(f"Error reading {file}: {e}")
        return pd.DataFrame()

# Load all collected data
systemInfo = read_csv("SystemInfo.csv")
hardwareInfo = read_csv("HardwareInfo.csv")
installedSoftware = read_csv("InstalledSoftware.csv")
userAccounts = read_csv("UserAccounts.csv")
runningProcesses = read_csv("RunningProcesses.csv")
networkConnections = read_csv("NetworkConnections.csv")
firewallStatus = read_csv("FirewallStatus.csv")
recentFileChanges = read_csv("RecentFileChanges.csv")
securityLogs = read_csv("SecurityLogs.csv")
powershellLogs = read_csv("PowerShellLogs.csv")
startupEntries = read_csv("StartupEntries.csv")
applicationLogs = read_csv("ApplicationLogs.csv")
systemLogs = read_csv("SystemLogs.csv")
firewallModificationEvents = read_csv("FirewallModificationEvents.csv")
scheduledTasks = read_csv("ScheduledTasks.csv")
USB = read_csv("USBDeviceHistory.csv")
admin_users_df = read_csv("AdminUsers.csv")
arp_table = read_csv("ARP_Table.csv")
dns_cache = read_csv("DNS_Cache.csv")
env_vars = read_csv("EnvironmentVariables.csv")
open_shares = read_csv("OpenShares.csv")
loaded_dlls = read_csv("LoadedDLLs.csv")
disk_info = read_csv("DiskInfo.csv")
volume_info = read_csv("VolumeInfo.csv")
smb=read_csv("SmbSessions.csv")


logging.basicConfig(filename="analyzer.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

if not runningProcesses.empty:
    missing_columns = {'Id', 'Path'} - set(runningProcesses.columns)
    if missing_columns:
        logging.error(f"Missing columns in RunningProcesses.csv: {missing_columns}")
    else:
        merged = pd.merge(
            networkConnections,
            runningProcesses[['Id', 'Path']],
            how='left',
            left_on='PID',
            right_on='Id'
        ).drop(columns=['Id']).rename(columns={'Path': 'CorrectedProcessPath'})
else:
    logging.error("RunningProcesses.csv is empty or not loaded correctly.")
    merged = pd.DataFrame()



def is_suspicious_port(port):
    uncommon = {4444, 1337, 31337, 5555, 6969}
    try:
        port = int(port)
    except:
        return False
    return port in uncommon or port >= 49152 or port == 0

def is_unusual_process_port(name, port):
    name = str(name).lower()
    try:
        port = int(port)
    except:
        return False
    safe_ports = {
        "chrome.exe": [80, 443],
        "firefox.exe": [80, 443],
        "msedge.exe": [80, 443],
        "safari.exe": [80, 443],
        "opera.exe": [80, 443],
        "explorer.exe": [],
        "lsass.exe": [88, 464, 389, 636, 3268, 3269],
        "wininit.exe": [],
        "services.exe": [],
        "winlogon.exe": [],
        "svchost.exe": list(range(1, 1024)),
        "mysqld.exe": [3306],
        "postgres.exe": [5432],
        "mongod.exe": [27017, 27018, 27019],
        "redis-server.exe": [6379, 6380],
        "nginx.exe": [80, 443, 8080],
        "apache.exe": [80, 443, 8080],
        "httpd.exe": [80, 443, 8080],
        "iisexpress.exe": [80, 443, 8080],
        "smtpd.exe": [25, 465, 587],
        "pop3d.exe": [110, 995],
        "imapd.exe": [143, 993],
        "rdpclip.exe": [3389],
        "mstsc.exe": [3389],
        "teamviewer.exe": [5938, 80, 443],
        "anydesk.exe": [7070, 80, 443],
        "filezilla.exe": [21, 22, 990],
        "winscp.exe": [21, 22, 990],
        "ftp.exe": [21, 990],
        "openvpn.exe": [1194, 443],
        "openconnect.exe": [443, 8443],
        "forticlient.exe": [443, 8443]
    }

    return port not in safe_ports.get(name, []) 

def is_internal_lateral(ip, port):
    try:    
        ip_obj = ipaddress.ip_address(ip)       # smb  RPC  RDP   winram
        return ip_obj.is_private and int(port) in {445, 135, 3389, 5985}
    except:
        return False

def rate_severity(reasons, ip_reputation):
    score = 0
    if ip_reputation == 'malicious': score += 3
    if ip_reputation == 'unknown': score += 1
    for r in reasons:
        if 'Malicious' in r: score += 3
        elif 'Abnormal' in r: score += 2
        elif 'off-hours' in r: score += 1
        elif 'Missing process path' in r: score += 1
    return 'Critical' if score >= 6 else 'High' if score >= 4 else 'Medium' if score >= 2 else 'Low'

def process_connection(connection, api_key, off_start=22, off_end=6):
    ip = str(connection.get('RemoteAddress', ''))
    if not ip or ip in ['127.0.0.1', '::1', '0.0.0.0'] or ip.startswith(('192.168.', '10.', '172.')):
        return None

    port = connection.get('RemotePort', 0)
    hash_value = str(connection.get('SHA256Hash', ''))
    proc_name = connection.get('ProcessName', '')
    proc_path = str(connection.get('CorrectedProcessPath', ''))
    time_collected = connection.get('TimeCollected', '')
    reasons = []

    ip_result = check_ip_reputation(ip, api_key)
    if ip_result == 'malicious':
        reasons.append("Malicious IP reputation")

    if is_suspicious_port(port):
        reasons.append(f"Unusual port used: {port}")

    try:
        is_malicious_hash, hash_msg = scan_hash_and_decide(hash_value, api_key)
        if is_malicious_hash:
            reasons.append(f"Malicious process hash: {hash_msg}")
    except Exception as e:
        reasons.append(f"VirusTotal scan error: {str(e)}")

    if is_unusual_process_port(proc_name, port):
        reasons.append(f"Abnormal port used by {proc_name}: {port}")

    if is_internal_lateral(ip, port):
        reasons.append("Possible lateral movement (internal service port)")

    if proc_path.lower() in ["", "nan", "none"]:
        reasons.append("Missing process path")



    if reasons:
        return {
            "Time Collected": str(time_collected),
            "Local Port": connection.get('LocalPort'),
            "Remote Address": ip,
            "Remote Port": port,
            "IP Reputation": ip_result,
            "State": str(connection.get('State')),
            "PID": connection.get('PID'),
            "Process Name": proc_name,
            "Process Path": proc_path,
            "Reasons": reasons,
            "Severity": rate_severity(reasons, ip_result)
        }
    return None

####################################################################################

# Setup logging format
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Patterns and heuristics
STANDARD_PATH_PATTERNS = [
    r'C:/Windows/System32', r'C:/Program Files', r'C:/Program Files \(x86\)', r'C:/Users/.*/AppData/Local'
]
SUSPICIOUS_PARENTS = {'cmd.exe', 'powershell.exe', 'python.exe', 'wscript.exe'}

KNOWN_LEGIT_NAMES = {
    'tcpsvcs', 'svchost', 'services', 'lsass', 'wininit', 'explorer', 'csrss', 'smss', 'winlogon',
    'dwm', 'conhost', 'taskhostw', 'msmpeng', 'spoolsv', 'dllhost', 'wuauclt', 'msdtc', 'audiodg',
    'sihost', 'ctfmon', 'searchindexer', 'runtimebroker', 'backgroundtransferhost', 'fontdrvhost',
    'securityhealthservice', 'wlanext', 'wlms', 'wbengine', 'wermgr', 'werfault', 'wscsvc', 'wmpnetwk',
    'wudfhost', 'wuauserv', 'trustedinstaller', 'tiworker', 'taskmgr', 'system', 'idle', 'msiexec',
    'regsvr32', 'rundll32', 'notepad', 'calc', 'mspaint', 'defrag', 'chkdsk', 'sfc', 'diskperf',
    'eventvwr', 'logonui', 'userinit', 'vssvc', 'sdclt', 'mobsync', 'igfxtray', 'hkcmd', 'igfxpers',
    'soundmixer', 'rdpclip', 'mstsc', 'tskmgr', 'perfmon', 'resmon', 'mmc', 'comsurrogate', 'sdiagnhost'
}

def is_random_name(name):
    name = str(name).lower().replace('.exe', '')
    if name in KNOWN_LEGIT_NAMES or len(name) < 5:
        return False
    entropy = len(set(name)) / len(name)
    has_vowels = any(c in 'aeiou' for c in name)
    has_numbers = any(c.isdigit() for c in name)
    return entropy > 0.8 and (not has_vowels or has_numbers) and name.isalnum()

def is_non_standard_path(path):
    path = str(path).replace('\\', '/')
    return not any(re.match(pat, path, re.IGNORECASE) for pat in STANDARD_PATH_PATTERNS)

def is_new_process(start_time):
    try:
        start_dt = datetime.strptime(str(start_time), '%m/%d/%Y %I:%M:%S %p')
        return (datetime.now() - start_dt).total_seconds() < 86400
    except Exception:
        return False

def has_base64_command_line(command_line):
    command_line = str(command_line)
    matches = re.findall(r'([A-Za-z0-9+/=]{20,})', command_line)
    for match in matches:
        try:
            if len(match) % 4 == 0:
                base64.b64decode(match, validate=True)
                return True
        except Exception:
            continue
    return False

def is_high_entropy_command(cmd):
    cleaned = re.sub(r'\W', '', str(cmd))
    if len(cleaned) < 10:
        return False
    entropy = len(set(cleaned)) / len(cleaned)
    return entropy > 0.85

def get_compile_time(filepath):
    try:
        pe = pefile.PE(filepath)
        timestamp = pe.FILE_HEADER.TimeDateStamp
        return datetime.utcfromtimestamp(timestamp)
    except:
        return None

def is_suspicious_parent(row, df):
    parent = str(row.get('ParentProcessName', '')).strip().lower()
    if not parent or parent == 'n/a':
        return True
    if 'system' in str(row.get('UserName', '')).lower():
        return False
    if parent.replace('.exe', '') in KNOWN_LEGIT_NAMES and not is_non_standard_path(str(row.get('Path'))):
        return False
    parent_exists = any(df['Name'].str.lower() == parent)
    return not parent_exists or is_random_name(parent.replace('.exe', ''))

def is_suspicious_parent_child(row):
    parent = str(row.get('ParentProcessName', '')).lower()
    child = str(row.get('Name', '')).lower()
    risky_children = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'python.exe', 'bash.exe']
    suspicious_parents = [
        'svchost.exe', 'services.exe', 'explorer.exe', 'winlogon.exe',
        'rundll32.exe', 'regsvr32.exe', 'msiexec.exe', 'dllhost.exe'
    ]
    if child in risky_children:
        return parent in suspicious_parents or is_random_name(parent.replace('.exe', ''))
    return False

def analyze_process(row, df):
    path = str(row.get('Path', ''))
    if not path or path in ('-', ''):
        return None
    reasons = []
    hash_value = None
    try:
        with open(path, 'rb') as f:
            hash_value = hashlib.sha256(f.read()).hexdigest()
    except FileNotFoundError:
        reasons.append("Path does not exist")
    except Exception as e:
        reasons.append(f"File read error: {e}")

    if is_random_name(row.get('Name')):
        reasons.append("Random-looking name")
    if is_non_standard_path(path):
        reasons.append("Non-standard path")
    if is_new_process(row.get('StartTime')):
        reasons.append("Recently started process")
    if is_suspicious_parent(row, df):
        if row.get('Name', '').lower() not in ['conhost.exe', 'firefox.exe', 'msedge.exe']:
            reasons.append("Suspicious parent process")
    if is_suspicious_parent_child(row):
        reasons.append("Suspicious parent-child pattern")
    if has_base64_command_line(row.get('CommandLine')):
        reasons.append("Base64 command line")
    if is_high_entropy_command(row.get('CommandLine')):
        reasons.append("High entropy command (likely obfuscated)")
       
        # Integrate file hash check
    if path and os.path.exists(path):
        hash_value = hashlib.sha256(open(path, 'rb').read()).hexdigest()
        is_malicious, message = scan_hash_and_decide(hash_value, API_KEYS[0])
        if is_malicious:
            reasons.append(f"Malicious file hash: {message}")

    if len(reasons) >= 2:
        return {
            'Id': row['Id'],
            'Name': str(row.get('Name', '')),
            'Path': path,
            'UserName': str(row.get('UserName', 'Unknown')),
            'CommandLine': str(row.get('CommandLine', '')),
            'Hash': hash_value,
            'StartTime': row.get('StartTime', ''),
            'ParentProcessName': row.get('ParentProcessName', ''),
            'ChildProcessName': row.get('ChildProcessName', ''),
            'Reasons': reasons
        }
    return None

def check_processes(df):
    results = []
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(analyze_process, row, df): i for i, row in df.iterrows()}
        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    results.append(res)
            except Exception as e:
                logging.warning(f"Analysis error: {e}")

    with ThreadPoolExecutor() as executor:
        hash_futures = {
            executor.submit(scan_hash_and_decide, proc['Hash'], API_KEYS[i % len(API_KEYS)]): i
            for i, proc in enumerate(results) if proc['Hash']
        }
        for future in as_completed(hash_futures):
            try:
                i = hash_futures[future]
                is_malicious, message = future.result()
                if is_malicious:
                    results[i]['Reasons'].append(f"VirusTotal: {message}")
            except Exception as e:
                logging.warning(f"Hash check error: {e}")

    return results

def print_suspicious_process(proc):
    print("\n" + "=" * 80)
    print(f"\033[91m⚠️ Suspicious Process Detected\033[0m")
    print(f"🆔  ID     : {proc.get('Id')}")
    print(f"📛 Name   : {proc.get('Name')}")
    print(f"📂 Path   : {proc.get('Path')}")
    print(f"🖥️  Command: {proc.get('CommandLine')}")
    print(f"👤 User   : {proc.get('UserName')}")
    print("🧾 Reasons:")
    for reason in proc.get('Reasons', []):
        print(f"   🔹 {reason}")
    print("=" * 80)
    
def check_unusual_processes(df_processes):
    cpu_threshold = 50.0
    memory_threshold = 1073741824  # 1GB
    unusual = df_processes[
        (df_processes['CPU'] > cpu_threshold) |
        (df_processes['WorkingSet'] > memory_threshold)
    ]
    return unusual[['Name', 'CPU', 'WorkingSet']].to_dict('records')

###########################################################

def check_unauthorized_software(df_software, user_accounts, opening_hour, closing_hour):
    # Load admin users

    admin_users = set(admin_users_df['Name'].dropna()) if not admin_users_df.empty else set()


    # Always include SYSTEM account
    admin_users.add('NT AUTHORITY\\SYSTEM')

    unauthorized = []

    for _, row in df_software.iterrows():
        install_time = pd.to_datetime(row.get('InstallTime'), errors='coerce')
        installed_by = str(row.get('InstalledBy', 'Unknown'))

        if pd.isna(install_time) or installed_by == 'Unknown':
            continue  # Skip invalid records

        reasons = []
        hour = install_time.hour

        if installed_by not in admin_users:
            reasons.append("Non-admin user")
        if hour < opening_hour or hour > closing_hour:
            reasons.append("Outside business hours")

        if reasons:
            unauthorized.append({
                'Name': str(row.get('Name', '')),
                'Install Time': str(install_time),
                'Installed By': installed_by,
                'Reason': ', '.join(reasons)
            })

    return unauthorized
#############################################################


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('startup_analysis.log'),
        logging.StreamHandler()
    ]
)

# Optimized function with multi-threading

def check_suspicious_startup_entries(df, gemini_keys, max_workers=10):
    df_filtered = df[~df['Name'].str.startswith('PS') & df['Value'].notna()]
    suspicious = []
    num_keys = len(gemini_keys)
    lock = threading.Lock()

    def process_entry(index, row):
        try:
            command = str(row.get('Value', ''))
            key = str(row['Key'])
            name = str(row.get('Name'))
            api_key = gemini_keys[index % num_keys]
            analysis = check_Startup(api_key, key, name, command)
            if analysis == 'suspicious':
                with lock:
                    suspicious.append({
                        'Key': key,
                        'Name': name,
                        'Command': command,
                        'Analysis': analysis
                    })
                    logging.info(f"Suspicious startup entry detected: {name} ({key})")
        except Exception as e:
            logging.error(f"Error analyzing startup entry '{name}': {e}")

    # Use ThreadPoolExecutor for parallel processing
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for i, row in df_filtered.iterrows():
            executor.submit(process_entry, i, row)

    return suspicious


################################################################
# Setup logging format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('firewall_modifications.log'),
        logging.StreamHandler()
    ]
)

# Optimized function with multi-threading

def check_firewall_modifications(df_firewall, gemini_keys, max_workers=10):
    if df_firewall.empty or not {'TimeCreated', 'Id', 'SubjectUserName', 'IpAddress', 'Message'}.issubset(df_firewall.columns):
        logging.warning("Empty DataFrame or missing required columns.")
        return []
    
    # Load admin users
    try:
        admin_users = set(admin_users_df['Name']) if not admin_users_df.empty else set()
    except FileNotFoundError:
        logging.error("AdminUsers.csv not found.")
        admin_users = set()
    admin_users.add('NT AUTHORITY\\SYSTEM')
    
    # Fill missing values
    df_firewall = df_firewall.fillna('')
    num_keys = len(gemini_keys)
    suspicious_entries = []
    lock = threading.Lock()

    def process_row(index, row):
        try:
            message = str(row['Message'])
            username = str(row['SubjectUserName'])
            event_id = str(row['Id'])
            ip_address = str(row['IpAddress'])
            time_created = str(row['TimeCreated'])
            api_key = gemini_keys[index % num_keys]
            content_result = check_message(api_key, message).strip().lower()
            is_non_admin = username not in admin_users
            if content_result == 'suspicious' or is_non_admin:
                reason = 'Suspicious content' if content_result == 'suspicious' else 'Non-admin change'
                with lock:
                    suspicious_entries.append({
                        'Time': time_created,
                        'Event ID': event_id,
                        'User': username,
                        'IP Address': ip_address,
                        'Message': message,
                        'Reason': reason
                    })
                    logging.info(f"Suspicious firewall modification detected: {message}")
        except Exception as e:
            logging.error(f"Error processing row {index}: {e}")

    # Use ThreadPoolExecutor for parallel processing
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for i, row in df_firewall.iterrows():
            executor.submit(process_row, i, row)

    return suspicious_entries

####################################################################################################

def csv_to_json():
    try:
        df = pd.read_csv(os.path.join(INPUT_DIR, "SuspiciousFiles.csv"))
        return {
            'files': [
                {
                    'FullName': str(row['FullName']).strip() if pd.notna(row['FullName']) else '',
                    'LastWriteTime': str(row['LastWriteTime']).strip() if pd.notna(row['LastWriteTime']) else '',
                    'SHA256Hash': str(row['SHA256Hash']).strip() if pd.notna(row['SHA256Hash']) else ''
                }
                for _, row in df.iterrows()
            ]
        }
    except Exception as e:
        return {'error': str(e)}

####################################################################
def analyze_recent_file_changes(df):
    suspicious_changes = []
    risky_extensions = {'.bat', '.vbs', '.ps1', '.exe', '.js', '.cmd'}
    risky_dirs = ["appdata", "temp", "programdata", "windows\\system32"]

    for _, row in df.iterrows():
        path = row.get("FullName", "").strip().lower()
        extension = os.path.splitext(path)[-1].lower()
        # Skip if path is empty
        if not path:
            continue
        
        # Check for risky extensions or directories
        if extension in risky_extensions or any(dir in path for dir in risky_dirs):
            suspicious_changes.append({
                "Path": row.get("FullName", ""),
                "ChangeType": "Modified",
                "Timestamp": row.get("LastWriteTime", ""),
                "Owner": row.get("Owner", "")
            })
    
    return suspicious_changes

####################################################################################################################


def analyze_event_ids_from_file( gemini_keys, max_workers=10):

    # Flat list of known Windows event IDs
    known_ids = [
        4625, 4624, 4740, 4698, 4702, 7045,
        4672, 4688, 4690, 4689, 4728, 4776,
        4798, 4756, 5140, 4769, 4104, 5145,
        5156, 1102, 4719, 1100
    ]

    # 1) Extract & filter
    event_ids = (
        securityLogs['Id']
        .dropna()
        .astype(int)
        .tolist()
    )
    matched_ids = [eid for eid in event_ids if eid in known_ids]
    print(f"Analyzing {len(matched_ids)} matched Event IDs...")
    print(matched_ids)
    if not matched_ids:
        return []

    try:
        # 2) Send single request: a JSON list
        api_key = gemini_keys[0]
        raw     = check_content(api_key, matched_ids)

        return raw
    

    except Exception as e:
        print(f"Error analyzing Event IDs: {e}")
        return [{"Error": str(e)}]


#######################################################################
def analyze_application_logs( gemini_keys, max_workers=10):

    # Flat list of known Windows event IDs
    known_ids = [
    1000, 1001, 1026, 1033, 4096, 4097, 6000, 8193, 8194, 
    1002, 5011, 4624, 4625, 7031, 7034, 1014, 11707, 11724, 
    104, 4098, 1005, 1502, 1503, 2001, 1003
    ]

    # 1) Extract & filter
    event_ids = (
        applicationLogs['Id']
        .dropna()
        .astype(int)
        .tolist()
    )
    matched_ids = [eid for eid in event_ids if eid in known_ids]
    print(f"Analyzing {len(matched_ids)} matched Event IDs...")
    print(matched_ids)
    if not matched_ids:
        return []

    try:
        # 2) Send single request: a JSON list
        api_key = gemini_keys[1]
        raw     = check_content2(api_key, matched_ids)


        return raw

    except Exception as e:
        print(f"Error analyzing Event IDs: {e}")
        return [{"Error": str(e)}]
###############################################################################33

def analyze_system_logs( gemini_keys, max_workers=10):

    # Flat list of known Windows event IDs
    known_ids = [
    4624, 4625, 4634, 4648, 4662, 4672, 4673, 4674, 4688, 4689, 
    4690, 4698, 4699, 4700, 4701, 4702, 4719, 4720, 4722, 4723, 
    4724, 4725, 4726, 4738, 4740, 4741, 4742, 4743, 4744, 4745, 
    4746, 4747, 4748, 4749, 4750, 4751, 4752, 4753, 4754, 4755, 
    4756, 4757, 4758, 4759, 4760, 4761, 4762, 4763, 4764, 4765, 
    4766, 4767, 4768, 4769, 4770, 4771, 4772, 4773, 4774, 4775, 
    4776, 4777, 4778, 4779, 4780, 4781, 4782, 4783, 4784, 4785, 
    4786, 4787, 4788, 4789, 4790, 4791, 4792, 4793, 4794, 4795, 
    4796, 4797, 4798, 4799, 4800, 4801, 4802, 4803, 4804, 4805, 
    4806, 4807, 4808, 4809, 4810, 4811, 4812, 4813, 4814, 4815, 
    4816, 4817, 4818, 4819, 4820, 4821, 4822, 4823, 4824, 4825, 
    4826, 4827, 4828, 4829, 4830, 4831, 4832, 4833, 4834, 4835, 
    4836, 4837, 4838, 4839, 4840, 4841, 4842, 4843, 4844, 4845, 
    4846, 4847, 4848, 4849, 4850, 4851, 4852, 4853, 4854, 4855, 
    4856, 4857, 4858, 4859, 4860, 4861, 4862, 4863, 4864, 4865, 
    4866, 4867, 4868, 4869, 4870, 4871, 4872, 4873, 4874, 4875, 
    4876, 4877, 4878, 4879, 4880, 4881, 4882, 4883, 4884, 4885, 
    4886, 4887, 4888, 4889, 4890, 4891, 4892, 4893, 4894, 4895, 
    4896, 4897, 4898, 4899, 4900, 4901, 4902, 4903, 4904, 4905, 
    4906, 4907, 4908, 4909, 4910, 4911, 4912, 4913, 4914, 4915, 
    4916, 4917, 4918, 4919, 4920, 4921, 4922, 4923, 4924, 4925, 
    4926, 4927, 4928, 4929, 4930, 4931, 4932, 4933, 4934, 4935, 
    4936, 4937, 4938, 4939, 4940, 4941, 4942, 4943, 4944, 4945, 
    4946, 4947, 4948, 4949, 4950, 4951, 4952, 4953, 4954, 4955, 
    4956, 4957, 4958, 4959, 4960, 4961, 4962, 4963, 4964, 4965, 
    4966, 4967, 4968, 4969, 4970, 4971, 4972, 4973, 4974, 4975, 
    4976, 4977, 4978, 4979, 4980, 4981, 4982, 4983, 4984, 4985, 
    4986, 4987, 4988, 4989, 4990, 4991, 4992, 4993, 4994, 4995, 
    4996, 4997, 4998, 4999
]


    # 1) Extract & filter
    event_ids = (
        applicationLogs['Id']
        .dropna()
        .astype(int)
        .tolist()
    )
    matched_ids = [eid for eid in event_ids if eid in known_ids]
    print(f"Analyzing {len(matched_ids)} matched Event IDs...")
    print(matched_ids)
    if not matched_ids:
        return []

    try:
        # 2) Send single request: a JSON list
        api_key = gemini_keys[2]
        raw     = check_content3(api_key, matched_ids)


        return raw

    except Exception as e:
        print(f"Error analyzing Event IDs: {e}")
        return [{"Error": str(e)}]
################################################################################

def analyze_scheduled_tasks(df):
    suspicious_tasks = []
    for _, row in df.iterrows():
        task_name = str(row.get("TaskName", ""))
        task_path = str(row.get("TaskPath", ""))
        author = str(row.get("Author", ""))
        description = str(row.get("Description", ""))
        
        # Check for potentially malicious indicators
        if re.search(r'powershell|cmd\.exe|\.ps1|wget|curl|certutil|rundll32|mshta', description, re.IGNORECASE):
            suspicious_tasks.append({
                "TaskName": task_name,
                "TaskPath": task_path,
                "Author": author,
                "Description": description
            })
    
    return suspicious_tasks



########################################################################################3
def analyze_arp_table(df_arp):
    """
    Check ARP table for duplicate MAC addresses or anomalies, excluding known multicast and broadcast addresses.
    """
    suspicious = []
    
    # Define known multicast and broadcast MAC prefixes
    multicast_ipv4_prefix = '01-00-5E'
    multicast_ipv6_prefix = '33-33'
    broadcast_mac = 'FF-FF-FF-FF-FF-FF'
    zero_mac = '00-00-00-00-00-00'
    
    # Group by MAC address and count occurrences
    mac_counts = df_arp['LinkLayerAddress'].value_counts()
    
    for mac, count in mac_counts.items():
        if count > 1:
            # Skip known multicast and broadcast MACs
            if (mac.startswith(multicast_ipv4_prefix) or 
                mac.startswith(multicast_ipv6_prefix) or 
                mac == broadcast_mac):
                continue
            # Handle zero MAC address separately
            elif mac == zero_mac:
                ips = df_arp[df_arp['LinkLayerAddress'] == mac]['IPAddress'].tolist()
                suspicious.append({
                    'MAC': mac,
                    'IPs': ips,
                    'Reason': 'Zero MAC address with multiple IPs (possibly unresolved entries)'
                })
            # Flag other duplicates as suspicious
            else:
                ips = df_arp[df_arp['LinkLayerAddress'] == mac]['IPAddress'].tolist()
                suspicious.append({
                    'MAC': mac,
                    'IPs': ips,
                    'Reason': f'Suspicious duplicate MAC address (count: {count})'
                })
    
    return suspicious

#####################################################################################
import math
import pandas as pd

def analyze_dns_cache(df_dns):
    """Check DNS cache for suspicious domain names with enhanced heuristics."""
    suspicious = []
    # Define common suspicious TLDs and keywords
    suspicious_tlds = {'cn', 'ru', 'tk', 'top', 'xyz', 'pw', 'info', 'buzz', 'zip', 'icu', 'click'}
    suspicious_keywords = ['malware', 'phish',   'ransom',  'ddos',
                            'attack', 'steal', 'hack', 'evil', 'shell', 'crypt', 'cn',
                             'bank', 'login', 'secure', 'update', 'account', 
        'verify', 'confirm', 'click', 'download', 'free', 'promo', 'offer', 'win', 
        'prize', 'alert', 'warning', 'error', 'virus', 'trojan', 'ransomware', 
        'spyware', 'adware', 'botnet', 'exploit', 'hack', 'scam', 'fraud', 'fake']

    for _, row in df_dns.iterrows():
        name = str(row['Name']).lower()
        data = row['Data']
        reason = []

        # Length Check
        if len(name) > 50:
            reason.append('Domain too long')
        
        # Keyword Check
        if any(kw in name for kw in suspicious_keywords):
            reason.append('Contains known malicious keyword')
        
        # TLD Check
        domain_parts = name.split('.')
        if len(domain_parts) > 1 and domain_parts[-1] in suspicious_tlds:
            reason.append('Suspicious TLD')
        
        # Entropy Check
        entropy = -sum((name.count(c) / len(name)) * math.log2(name.count(c) / len(name)) for c in set(name))
        if entropy > 4.0:
            reason.append('High entropy domain (potential DGA)')
        
        # Numeric Domain Check
        if sum(c.isdigit() for c in name) > 10:
            reason.append('Excessive numeric characters')
        
        # Punycode Check
        if name.startswith('xn--'):
            reason.append('Punycode domain (possible homograph attack)')
        
        # Unusual Character Check
        if re.search(r'[^a-z0-9.-]', name):
            reason.append('Contains unusual characters')
        
        # If any reason matched, add to suspicious list
        if reason:
            suspicious.append({
                'Domain': name,
                'Data': data,
                'Reason': ', '.join(reason)
            })

    return suspicious



##################################################################################33
def analyze_environment_variables(df_env):
    """Check for suspicious environment variables with enhanced heuristics."""
    suspicious = []
    standard_vars = {
        'PATH', 'WINDIR', 'SYSTEMROOT', 'COMSPEC', 'PATHEXT', 'TEMP', 'TMP', 
        'PROGRAMFILES', 'PROGRAMFILES(X86)', 'USERPROFILE', 'HOMEPATH', 
        'SYSTEMDRIVE', 'ALLUSERSPROFILE', 'APPDATA', 'LOCALAPPDATA'
    }
    
    # Common malicious keywords
    malicious_keywords = ['malware', 'trojan', 'exploit', 'hack', 'backdoor', 'meterpreter', 'cobaltstrike', 'payload', 'obfuscate', 'shell', 'reverse', 'bot', 'beacon']
    
    # Potentially dangerous extensions
    dangerous_extensions = ['.exe', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.msc', '.cpl', '.ps1', '.psm1', '.dll', '.scr', '.hta']
    
    for _, row in df_env.iterrows():
        name = str(row['Name']).upper().strip()
        value = str(row['Value']).lower().strip()
        reasons = []
        
        # Non-standard variable pointing to executables
        if name not in standard_vars and any(ext in value for ext in dangerous_extensions):
            reasons.append("Non-standard variable pointing to executable")
        
        # Malicious keyword detection
        if any(keyword in value for keyword in malicious_keywords):
            reasons.append("Contains known malicious keyword")
        
        # Hidden directories check
        if re.search(r'\\\.', value):
            reasons.append("Points to hidden or uncommon directory")
        
        # Binary path check
        if re.search(r'\\(bin|scripts)\\', value):
            reasons.append("Contains potential binary directory")
        
        # Path traversal check
        if '..' in value or '/..' in value or '\\..' in value:
            reasons.append("Potential path traversal")
        
        # Add to suspicious if any reason matched
        if reasons:
            suspicious.append({
                'Name': name,
                'Value': value,
                'Reason': ', '.join(reasons)
            })
    
    return suspicious




#################################################################################
import pandas as pd

def analyze_open_shares(df_shares):
    """Check for shares with weak permissions, sensitive directories, and unusual paths."""
    suspicious = []
    
    # Known sensitive and risky paths
    risky_paths = [
        r'.*\\temp\\.*', r'.*\\tmp\\.*', r'.*\\users\\public\\.*', 
        r'.*\\inetpub\\.*', r'.*\\windows\\.*', r'.*\\system32\\.*', 
        r'.*\\syswow64\\.*', r'.*\\programdata\\.*', r'.*\\appdata\\.*'
    ]
    
    # Known default and administrative shares
    default_shares = {'admin$', 'c$', 'd$', 'e$', 'ipc$', 'print$', 'sysvol', 'netlogon'}
    
    # Check each share for potential issues
    for _, row in df_shares.iterrows():
        name = str(row['Name']).lower().strip()
        path = str(row['Path']).lower().strip() if pd.notna(row['Path']) else ''
        description = str(row['Description']).lower().strip() if pd.notna(row['Description']) else ''
        
        reasons = []
        
        # Check for default and administrative shares
        if name in default_shares:
            reasons.append("Default or administrative share")
        
        # Check for risky paths
        if any(re.match(pattern, path) for pattern in risky_paths):
            reasons.append("Exposes potentially sensitive directory")
        
        # Check for public or temporary shares
        if 'public' in name or 'everyone' in name or 'guest' in name:
            reasons.append("Potentially insecure share (public access)")
        
        # Check for anonymous access
        if 'ipc$' in name and not path:
            reasons.append("Anonymous access (potential security risk)")
        
        # Check for potentially dangerous descriptions
        if 'remote' in description or 'admin' in description:
            reasons.append("Exposes potentially sensitive service")
        
        # Add to suspicious if any reason matched
        if reasons:
            suspicious.append({
                'Name': name,
                'Path': path,
                'Description': description,
                'Reason': ', '.join(reasons)
            })
    
    return suspicious



################################################################################3

def analyze_smb_sessions(df_sessions):
    """Check SMB sessions for unusual clients, users, and connection patterns."""
    suspicious = []
    
    # Define private IP ranges for local networks
    private_ip_ranges = [
        r'^192\.168\.', r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', r'^127\.0\.0\.1'
    ]
    
    # Define common guest and suspicious usernames
    suspicious_usernames = ['guest', 'anonymous', 'admin', 'administrator', 'root', 'support', 'test', 'backup']
    malicious_patterns = ['test', 'backup', 'scanner', 'bot', 'spider', 'crawler', 'attack', 'exploit', 'pwn', 'hacker']
    
    # Process each session
    for _, row in df_sessions.iterrows():
        client_ip = str(row['ClientComputerName']).strip()
        user = str(row['ClientUserName']).lower().strip()
        reason = []
        
        # Check for external IP addresses
        if not any(re.match(pattern, client_ip) for pattern in private_ip_ranges):
            reason.append("External IP address")
        
        # Check for guest or suspicious usernames
        if any(keyword in user for keyword in suspicious_usernames):
            reason.append("Guest or suspicious username")
        
        # Check for known malicious patterns in usernames
        if any(keyword in user for keyword in malicious_patterns):
            reason.append("Known malicious username pattern")
        
        # Check for unusually long or random-looking usernames (possible automated attack)
        if len(user) > 20 or re.match(r'^[a-z0-9]{16,}$', user):
            reason.append("Unusually long or random username")
        
        # Add to suspicious if any reason matched
        if reason:
            suspicious.append({
                'ClientIP': client_ip,
                'User': user,
                'Reason': ', '.join(reason)
            })
    
    return suspicious
#####################################################3333
#################################################################################
def analyze_loaded_dlls(df_dlls):
    """Check for DLLs loaded from unusual locations."""
    suspicious = []
    standard_paths = ['c:/windows/system32', 'c:/program files','c:/program files \(x86\)']
    for _, row in df_dlls.iterrows():
        path = str(row['DLLPath']).lower().replace('\\', '/')
        if not any(p in path for p in standard_paths):
            suspicious.append({
                'ProcessName': row['ProcessName'],
                'DLLName': row['DLLName'],
                'DLLPath': path,
                'Reason': 'Loaded from non-standard path'
            })
    return suspicious
###############################################################################
def analyze_disk_info(df_disk):
    """Check for unusual disk configurations and potential issues."""
    suspicious = []
    
    # Define thresholds for unusually small or large disks (adjust as needed)
    small_disk_threshold = 1024 * 1024 * 1024  # 1 GB
    large_disk_threshold = 10 * 1024 * 1024 * 1024 * 1024  # 10 TB
    
    for _, row in df_disk.iterrows():
        style = str(row['PartitionStyle']).strip().upper()
        size = int(row['Size'])
        name = str(row['FriendlyName']).strip()
        reasons = []
        
        # Check for RAW partitions
        if style == 'RAW':
            reasons.append("RAW partition style (unformatted)")
        
        # Check for unusually small or large disks
        if size < small_disk_threshold:
            reasons.append("Unusually small disk size (< 1GB)")
        elif size > large_disk_threshold:
            reasons.append("Unusually large disk size (> 10TB)")
        
        # Check for removable or suspicious disk names
        if any(keyword in name.lower() for keyword in ['usb', 'jmicron', 'sd', 'external', 'backup', 'virtual', 'vhd']):
            reasons.append("Potentially removable or external drive")
        
        # Add to suspicious if any reason matched
        if reasons:
            suspicious.append({
                'Number': row['Number'],
                'Name': name,
                'Size': size,
                'PartitionStyle': style,
                'Reason': ', '.join(reasons)
            })
    
    return suspicious
############################################################################
def analyze_volume_info(df_volume):
    """Check for volumes without drive letters or unusual configurations."""
    suspicious = []
    
    # Define thresholds for unusually small or large volumes (adjust as needed)
    small_volume_threshold = 100 * 1024 * 1024  # 100 MB
    large_volume_threshold = 10 * 1024 * 1024 * 1024 * 1024  # 10 TB
    low_free_space_ratio = 0.1  # Less than 10% free space
    
    # Common temporary or suspicious volume labels
    suspicious_labels = ['recovery', 'system', 'temp', 'backup', 'cache', 'reserved', 'unknown', 'new volume', 'windows']
    
    for _, row in df_volume.iterrows():
        drive = str(row['DriveLetter']).strip() if pd.notna(row['DriveLetter']) else ''
        label = str(row['FileSystemLabel']).strip().lower()
        filesystem = str(row['FileSystem']).strip().upper()
        size = int(row['Size'])
        size_remaining = int(row['SizeRemaining'])
        reasons = []
        
        # Check for volumes without drive letters
        if not drive:
            reasons.append("No drive letter assigned")
        
        # Check for suspicious or temporary volume labels
        if any(keyword in label for keyword in suspicious_labels):
            reasons.append("Suspicious or temporary volume label")
        
        # Check for unusually small or large volumes
        if size < small_volume_threshold:
            reasons.append("Unusually small volume size (< 100MB)")
        elif size > large_volume_threshold:
            reasons.append("Unusually large volume size (> 10TB)")
        
        # Check for low free space
        if size > 0 and (size_remaining / size) < low_free_space_ratio:
            reasons.append("Low free space (< 10%)")
        
        # Add to suspicious if any reason matched
        if reasons:
            suspicious.append({
                'DriveLetter': drive,
                'Label': label,
                'FileSystem': filesystem,
                'Size': size,
                'FreeSpace': size_remaining,
                'Reason': ', '.join(reasons)
            })
    
    return suspicious

