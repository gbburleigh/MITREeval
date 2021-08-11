import sys, os, json, csv

class StatsRef:
    def __init__(self):
        pass

    def __attacks__(self):
        attacks = {
            "Privilege Escalation": {
                "Abuse Elevation Control Mechanism": ["Bypass User Account Control"],
                "Access Token Manipulation": ["Create Process with Token", "Token Impersonation/Theft"],
                "Boot or Logon Autostart Execution": ["Registry Run Keys / Startup Folder"],
                "Create or Modify System Process": ["Windows Service"],
                "Event Triggered Execution": ["Application Shimming",
                                            "Component Object Model Hijacking",
                                            "Accessibility Features",
                                            "Management Instrumentation Event Subscription"],
                "Hijack Execution Flow": ["DLL Search Order Hijacking"],
                "Process Injection": ["", "Process Hollowing"],
                "Scheduled Task/Job": ["Scheduled Task"],
                "Valid Accounts": ["Domain Accounts"],
            },
            "Discovery": {
                "Application Window Discovery": [""],
                "Account Discovery": ["Domain Account", "Local Account"],
                "File and Directory Discovery": [""],
                "Network Share Discovery": [""],
                "Password Policy Discovery": [""],
                "Peripheral Device Discovery": [""],
                "Permission Groups Discovery": ["Domain Groups", "Local Groups"],
                "Process Discovery": [""],
                "Query Registry": [""],
                "Remote System Discovery": [""],
                "Software Discovery": ["Security Software Discovery"],
                "System Information Discovery": [""],
                "System Network Configuration Discovery": [""],
                "System Network Connections Discovery": [""],
                "System Owner/User Discovery": [""],
                "System Service Discovery": [""],
                "Virtualization/Sandbox Evasion": ["System Checks"],
            },
            "Credential Access": {
                "Brute Force": ["Password Spraying"],
                "Credentials from Password Stores": ["Credentials from Web Browsers"],
                "Input Capture": ["Keylogging"],
                "OS Credential Dumping": ["LSASS Memory", "Security Account Manager"],
                "Unsecured Credentials": ["Credentials in Files", "Private Keys"],
            },
            "Command and Control": {
                "Application Layer Protocol": ["", "DNS", "Web Protocols"],
                "Data Encoding": ["Standard Encoding"],
                "Encrypted Channel": ["Asymmetric Cryptography", "Symmetric Cryptography"],
                "Ingress Tool Transfer": [""],
                "Non-Application Layer Protocol": [""],
                "Proxy": [""],
                "Remote Access Software": [""],
                "Commonly Used Port": [""],
                "Web Service": [""],
            },
            "Collection": {
                "Archive Collected Data": ["Archive via Utility"],
                "Automated Collection": [""],
                "Clipboard Data": [""],
                "Data from Local System": [""],
                "Data from Network Shared Drive": [""],
                "Email Collection": ["Local Email Collection"],
                "Data Staged": ["Local Data Staging", "Remote Data Staging"],
                "Screen Capture": [""],
            },
            "Execution": {
                "Command and Scripting Interpreter": ["", 
                                                    "JavaScript/Jscript", 
                                                    "PowerShell",
                                                    "Visual Basic",
                                                    "Windows Command Shell"],
                "Inter-Process Communication": ["Component Object Model"],
                "Native API": [""],
                "System Services": ["Service Execution"],
                "User Execution": ["Malicious File"],
                "Windows Management Instrumentation": [""],
            },
            "Defense Evasion": {
                "Deobfuscate/Decode Files or Information": [""],
                "File and Directory Permissions Modification": ["Windows File and Directory Permissions Modification"],
                "Hide Artifacts": ["NTFS File Attributes"],
                "Indicator Removal on Host": ["File Deletion", "Network Share Connection Removal", "Timestomp"],
                "Impair Defenses": ["Disable or Modify System Firewall"],
                "Masquerading": ["", 
                                "Masquerade Task or Service", 
                                "Match Legitimate Name or Location", 
                                "Rename System Utilities", 
                                "Right to Left Override"],
                "Modify Registry": [""],
                "Obfuscated Files or Information": ["", "Software Packing", "Steganography"],
                "Signed Binary Proxy Execution": ["Mshta", "Rundll32"],
                "Use Alternate Authentication Material": ["Pass the Hash", "Pass the Ticket"],
            },
            "Lateral Movement": {
                "Remote Services": ["Remote Desktop Protocol", "SMB/Windows Admin Shares", "SSH", "Windows Remote Management"],
                "Lateral Tool Transfer": [""],
            },
            "Persistence": {
                "Create Account": ["Local Account"],
            },
            "Exfiltration": {
                "Exfiltration Over Alternative Protocol": ["", "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol"],
                "Exfiltration Over Command and Control Channel": [""],
                "Exfiltration Over Web Service": ["Exfiltration to Cloud Storage"]
            }
        }
        return attacks

    def __colormap__(self):
        colormap = {
            "Privilege Escalation": "cyan",
            "Discovery": "blue",
            "Credential Access": "yellow",
            "Command and Control": "orange",
            "Collection": "green",
            "Execution": "pink",
            "Defense Evasion": "purple",
            "Lateral Movement": "fuchsia",
            "Persistence": "maroon",
            "Exfiltration": "olivedrab"
            }
        return colormap

    def __data_sources__(self):
        return ['Process Monitoring', 'DLL Monitoring', 'File Monitoring', 'Network Monitoring', \
            'Script Logs', 'Windows Registry', 'Windows Event Logs', 'Authentication Logs', \
            'System Calls/API Monitoring', 'Sandbox', 'Named Pipes', 'WMI Objects', \
            'Machine Learning', 'ETW', 'SONAR / Endpoint Detection', 'Command-Line Parameters / AMSI', \
            'Networking / AMSI', 'Network connection , ETW', 'RPC', 'Memory Analysis', 'Cynet AV', 'Memory Scanning/Signatures', 'Signatures in memory', 'Behavior rules']

    def __evaluations__(self):
        return ['apt3', 'apt29', 'carbanak_fin7']

    def __participants__(self):
        participants = [
            "AhnLab", "Cybereason", "Fidelis", "Malwarebytes", "RSA", "TrendMicro", "Bitdefender",
            "Cylance", "FireEye", "McAfee", "ReaQta", "Uptycs", "CheckPoint", "Cynet", "Fortinet",
            "MicroFocus", "Secureworks", "VMware", "Cisco", "ESET", "GoSecure", "Microsoft", "SentinelOne",
            "CrowdStrike", "Elastic", "HanSight", "OpenText", "Sophos", "CyCraft", "F-Secure", "Kaspersky",
            "PaloAltoNetworks", "Symantec"]
        return participants

    def __countries__(self):
        countries = {
            "South Korea": ["AhnLab"],
            "United States": ["Cybereason", "Fidelis", "Malwarebytes", "RSA", "Cylance", "FireEye", "McAfee"
                            "Uptycs", "Fortinet", "Secureworks", "VMWare", "Cisco", "Microsoft", "SentinelOne",
                            "CrowdStrike", "PaloAltoNetworks", "Symantec"],
            "Japan": ["TrendMicro"],
            "Taiwan": ["CyCraft"],
            "Romania": ["Bitdefender"],
            "Netherlands": ["ReaQta", "Elastic"],
            "Israel": ["CheckPoint", "Cynet"],
            "United Kingdom": ["MicroFocus", "Sophos"],
            "Slovakia": ["ESET"],
            "Canada": ["GoSecure", "OpenText"],
            "China": ["HanSight"],
            "Finland": ["F-Secure"],
            "Russia": ["Kaspersky"]}
        return countries

    def __scoring__(self):
        scoring = { 
            ('SpecificBehavior'):5,                                          \
            ('SpecificBehavior, Tainted'):5,                                  \
            ('Technique'):5,                                  \
            ('Technique, Tainted'):5,                                  \
            ('GeneralBehavior'):4,                                           \
            ('GeneralBehavior, Tainted'):4,                                  \
            ('Tactic'):4,                                  \
            ('Tactic, Tainted'):4,                                  \
            ('General'):4,                                           \
            ('General, Tainted'):4,                                  \
            ('SpecificBehavior, Delayed'):3,                                 \
            ('GeneralBehavior, Delayed'):2,                                   \
            ('Tactic, Delayed'):2,                                  \
            ('Technique, Delayed'):3,                                   \
            ('Enrichment'):3,                                                 \
            ('Enrichment, Tainted'):3,                                         \
            ('Enrichment, Delayed'):1,                                        \
            ('Telemetry'):1,                                                  \
            ('Telemetry, Tainted'):1,                                         \
            ('Telemetry, Delayed'):0,                                         \
            ('IndicatorofCompromise'):0,                                    \
            ('IndicatorofCompromise, Tainted'):0,
            ('IndicatorofCompromise, Delayed'):0,                           \
            ('None'):0 ,
            ('MSSP'): 0,
            ('MSSP', 'Tainted'): 0,
            ('MSSP', 'Delayed'): 0}
        return scoring

    def __grading__(self):
        grade_scale = {
            "Excellent": (85, 100),
            "Very Good": (70, 85),
            "Good": (55, 70),
            "Fair": (40, 55),
            "Poor": (0, 40)}
        return grade_scale

    def __detections__(self):
        return {
            'apt3': 'N/A None Telemetry IndicatorofCompromise Enrichment GeneralBehavior SpecificBehavior',
            'apt29': 'N/A None MSSP Telemetry General Tactic Technique',
            'carbanak_fin7': 'N/A None Telemetry General Tactic Technique'
        }

    def __participants_by_eval__(self):
        return {'apt3': ['Elastic', 'McAfee', 'F-Secure', 'CrowdStrike', 'FireEye', 'RSA', 'Cybereason', 'Microsoft', 'PaloAltoNetworks', 'GoSecure', 'SentinelOne'], 
        'apt29': ['Elastic', 'McAfee', 'Kaspersky', 'VMware', 'F-Secure', 'CrowdStrike', 'FireEye', 'TrendMicro', 'Symantec', 'Cybereason', 'Malwarebytes', 'HanSight', 'Microsoft', 'PaloAltoNetworks', 'Secureworks', 'Bitdefender', 'Cylance', 'GoSecure', 'SentinelOne', 'CyCraft', 'ReaQta'], 
        'carbanak_fin7': ['Elastic', 'McAfee', 'VMware', 'F-Secure', 'CrowdStrike', 'FireEye', 'TrendMicro', 'Symantec', 'Cybereason', 'Uptycs', 'Malwarebytes', 'MicroFocus', 'Cisco', 'Cynet', 'Sophos', 'CheckPoint', 'AhnLab', 'Microsoft', 'OpenText', 'PaloAltoNetworks', 'Bitdefender', 'Cylance', 'GoSecure', 'SentinelOne', 'ESET', 'Fidelis', 'CyCraft', 'Fortinet', 'ReaQta']}

    def __modifiers__(self):
        return {
            'apt3': ['Tainted'],
            'apt29': ['Correlated', 'Innovative'],
            'carbanak_fin7': []
        }

    def get_references(self):
        a = self.__attacks__()
        c = self.__colormap__()
        e = self.__evaluations__()
        p = self.__participants__()
        cs = self.__countries__()
        s = self.__scoring__()
        g = self.__grading__()
        d = self.__detections__()
        m = self.__modifiers__()
        pe = self.__participants_by_eval__()

        return a, c, e, p, cs, s, g, d, m, pe

if __name__ == '__main__':
    r = StatsRef()
    a, c, e, p, cs, s, g = r.get_references()
