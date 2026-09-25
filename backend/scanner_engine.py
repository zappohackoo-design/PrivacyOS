import re
import json

def scan_source_code(code_text: str):
    vulnerabilities = []
    
    # 1. Regex patterns for hardcoded secrets
    patterns = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
        "Hardcoded Password / Secret": r"(password|secret|api_key|token)\s*=\s*['\"].*?['\"]",
        "Database Connection String": r"(postgres|mysql|mongodb)(\+srv)?://[^\s]+",
        "Potential SQL Injection Vector": r"cursor\.execute\(\s*f?['\"].*?%s|format\(",
        "Insecure MD5/SHA1 Hashing": r"hashlib\.(md5|sha1)"
    }
    
    lines = code_text.splitlines()
    for line_num, line in enumerate(lines, 1):
        for vuln_name, pattern in patterns.items():
            if re.search(pattern, line, re.IGNORECASE):
                vulnerabilities.append({
                    "line": line_num,
                    "type": vuln_name,
                    "snippet": line.strip()
                })
                
    # Calculate security grade based on findings
    count = len(vulnerabilities)
    if count == 0:
        grade = "A"
    elif count <= 2:
        grade = "B"
    elif count <= 4:
        grade = "C"
    elif count <= 6:
        grade = "D"
    else:
        grade = "F"
        
    return {
        "grade": grade,
        "total_vulnerabilities": count,
        "findings": vulnerabilities
    }