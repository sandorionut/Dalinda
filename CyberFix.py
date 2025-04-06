import difflib
import json
import shutil
from pathlib import Path
import openai
import subprocess
import os

# Load configuration
with open('config.json') as f:
    config = json.load(f)
OPENAI_API_KEY = config['openai_api_key']
BACKUP_DIR = Path('backup')

# Initialize OpenAI client
openai.api_key = OPENAI_API_KEY

import json
from pathlib import Path

sudo_password = "andrei"

def run_nuclei_scan():
    # Expand the path to the nuclei binary
    nuclei_path = os.path.expanduser("~/go/bin/nuclei")

    # Your full command as a list
    command = [
        nuclei_path,
        "-t", os.path.expanduser("~/go/bin/nuclei-templates"),
        "-u", "http://localhost/sqli_1.php?title=%27&action=search",
        "-H", "Cookie: security_level=0;PHPSESSID=rubqak1c72ll1t59gq4526ork3",
        "-es", "info,low,medium,high,unknown",
        "-json-export", "scan.json"
    ]

    # Run the command and capture output
    try:
        result = subprocess.run(command, check=True, text=True, capture_output=True)
        print("✅ Command ran successfully.")
    except subprocess.CalledProcessError as e:
        print("❌ Error running command:")
    except FileNotFoundError as fnf:
        print(f"❌ File not found: {fnf}")


def parse_json_output():
    """Parse the JSON output file and extract only the SQL syntax vulnerability"""
    vulnerabilities = []
    with open('scan.json') as jsonfile:
        data = json.load(jsonfile)
        for entry in data:
            if any("SQL syntax" in result for result in entry.get('extracted-results', [])):
                file_name = Path(entry.get('path', 'sqli_1.php')).name
                vulnerabilities.append({
                    'host': entry.get('host', ''),
                    'file': file_name,  # Use only the file name
                    'severity': entry['info'].get('severity', ''),
                    'description': entry['info'].get('description', '')
                })
    print(vulnerabilities)
    return vulnerabilities


def generate_fix_prompt(vuln, file_content):
    """Forțează returnarea codului complet, cu fixuri doar în zona vulnerabilă"""
    return f"""
    VULNERABILITY FIX REQUEST (Fix the issues in the code):
    {json.dumps(vuln, separators=(',', ':'))}
    
    The fix should follow the best practices for the current language and frameworks and should not introduce any new vulnerabilities.
    
    ORIGINAL CODE (COPY-PASTE EXACT):
    {file_content}
    
    FIX RULES (CRITIC):
    1. Return the whole code from the given input; dont show me differences
    2. Modify just the lines that are identified as vulnerable
    3. Don't add any comments, but show the original comments from the given code
    4. Keep the same indentation and structure of the code
    
    Important: RETURN THE WHOLE CODE without shortening it or omitting any part. No yapping, no explanations, just the code.
    """.strip()

def call_openai(prompt):
    """Send prompt to OpenAI and return the response"""
    response = openai.ChatCompletion.create(
        model="gpt-4o",
        messages=[
            {"role": "system",
             "content": "You are a cybersecurity expert. You are tasked with fixing vulnerabilities in a codebase. Your job is to provide the best possible (based on the nuclei tool) fix for the given code. You will follow the best practices for the current language and frameworks and will not introduce any new vulnerabilities."},
            {"role": "user", "content": prompt}
        ]
    )
    return response.choices[0].message['content']

def read_file(file_path):
    """Read the content of a file"""
    with open(file_path, 'r') as file:
        return file.readlines()

def compare_files(original_file, modified_file):
    """Compare two files and display differences with emoticons"""
    original_lines = read_file(str(original_file))
    modified_lines = read_file(str(modified_file))

    differences = list(difflib.unified_diff(
        original_lines, modified_lines, fromfile=str(original_file), tofile=str(modified_file), lineterm=''
    ))

    if not differences:
        print("✅ Identical files.")
        return False

    print("\n📊 Detected differences:\n")

    # Initialize line numbering for each file
    numar_linie_fisier1 = 1
    numar_linie_fisier2 = 1

    for linie in differences:
        if linie.startswith('---'):
            # Display original file
            print(f"\n📁 Original file: \033[96m{linie[4:]}\033[0m")
        elif linie.startswith('+++'):
            # Display modified file
            print(f"📁 Modified file: \033[96m{linie[4:]}\033[0m")
        elif linie.startswith('@@'):
            # Explain the comparison block
            parts = linie.split()
            original = parts[1]  # ex: -1,14
            modificat = parts[2]  # ex: +1,31

            original_start, original_lines = original[1:].split(',')
            modificat_start, modificat_lines = modificat[1:].split(',')

            print(f"\n🔍 Comparing:")
            print(f"   - 📌 Original file: {original_start}, {original_lines} (starting line, number of lines)")
            print(f"   - 🆕 Modified file: {modificat_start}, {modificat_lines} (starting line, number of lines)")
        elif linie.startswith('-'):
            # Deleted line
            print(f"❌  Line {numar_linie_fisier1}(Original): \033[91m{linie[1:].rstrip()}\033[0m")
            numar_linie_fisier1 += 1  # Increment line number in the original file
        elif linie.startswith('+'):
            # Added line
            print(f"✅  Line {numar_linie_fisier2}(Modified): \033[92m{linie[1:].rstrip()}\033[0m")
            numar_linie_fisier2 += 1  # Increment line number in the modified file
        else:
            print(f"   Unchanged : {linie.rstrip()}")
            # Increment line number for each file
            if linie[0] != '-':
                numar_linie_fisier1 += 1
            if linie[0] != '+':
                numar_linie_fisier2 += 1

    return True

def apply_code_fix(file_path, fix_code):
    """Apply the fix to the vulnerable file"""
    # Create backup
    backup_path = BACKUP_DIR / f"{file_path.stem}.bak"
    shutil.copy(file_path, backup_path)

    # Extract PHP code from OpenAI response
    code_start = fix_code.find("```php") + 6
    code_end = fix_code.rfind("```")
    clean_code = fix_code[code_start:code_end].strip()

    # Write the fixed code to a temporary file
    temp_file_path = file_path.with_suffix('.tmp')
    with open(temp_file_path, 'w') as f:
        f.write(clean_code)

    # Compare the original and fixed files
    if compare_files(file_path, temp_file_path):
        # Prompt the user for confirmation
        choice = input("Change [Y/n]: ").strip().lower()
        if choice == 'y':
            shutil.move(temp_file_path, file_path)
            print("[✓] Fix applied successfully!")
        else:
            temp_file_path.unlink()
            print("[✗] Fix not applied.")
    else:
        temp_file_path.unlink()

    # # Overwrite the file with the fixed code
    # with open(file_path, 'w') as f:
    #     f.write(clean_code)



def main():
    #run_nuclei_scan()

    # Create backup directory
    BACKUP_DIR.mkdir(exist_ok=True)

    # Parse the JSON output
    vulnerabilities = parse_json_output()

    for vuln in vulnerabilities:
        file_path = Path(vuln['file'])

        print(f"\n[+] Processing: {file_path}")

        # Read the full content of the file
        with open(file_path, 'r') as file:
            file_content = file.read()

        prompt = generate_fix_prompt({
            'file': str(file_path),
            'severity': vuln['severity'],
            'description': vuln['description']
        }, file_content)

        # Get the fix from OpenAI
        print("[*] Generating fix via OpenAI...")
        fix_code = call_openai(prompt)

        # Apply the fix
        print(f"[*] Applying fix to {file_path}...")
        apply_code_fix(file_path, fix_code)
        # print("[✓] Fix applied successfully!")


if __name__ == "__main__":
    main()
