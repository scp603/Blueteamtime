#!/bin/bash
# Nine-Tailed Fox - Flag Hunter & Decoy Generator
# Focus: Finds CONFIDENTIAL{...} flags and deploys 100 decoys per directory.

echo "=== Nine-Tailed Fox: Flag Decoy Operation ==="
echo "[+] Starting hunt for 'CONFIDENTIAL{' flags..."

# We search common directories where flags usually hide. 
# You can change this to "/" for the whole machine, but it will take much longer.
SEARCH_DIRS="/root /home /var/www /opt /etc /tmp /usr/local"

# Find files containing the exact string "CONFIDENTIAL{"
# 2>/dev/null hides permission denied errors so the output stays clean
FOUND_FILES=$(grep -rl "CONFIDENTIAL{" $SEARCH_DIRS 2>/dev/null)

if [ -z "$FOUND_FILES" ]; then
    echo "[-] No flags found in $SEARCH_DIRS."
    echo "    They might be in an unusual location, or named differently."
    exit 0
fi

echo "[!] Flags discovered:"

for FILE in $FOUND_FILES; do
    echo "  -> Found real flag file: $FILE"
    
    # Get the directory where the real flag lives
    FLAG_DIR=$(dirname "$FILE")
    
    echo "  [+] Deploying 100 decoy flags in $FLAG_DIR..."
    
    # Generate 100 fake flag files
    for i in {1..100}; do
        # Generate a random 12-character alphanumeric string
        RAND_STR=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 12)
        
        # Create a fake flag using the exact required format and random string
        FAKE_FLAG="CONFIDENTIAL{f4k3_${RAND_STR}_s3cr3t}"
        
        # Pick a random, tempting filename for the decoy
        NAMES=("backup" "creds" "db_dump" "secret" "notes" "service_key" "admin_pass")
        RAND_NAME=${NAMES[$RANDOM % ${#NAMES[@]}]}
        
        # Write the fake flag to the new fake file
        echo "$FAKE_FLAG" > "$FLAG_DIR/${RAND_NAME}_${i}.txt"
    done
    
    echo "  [+] 100 decoys successfully deployed in $FLAG_DIR."
    # Change permissions so Red Team can read them (and get confused)
    chmod 644 $FLAG_DIR/*.txt 2>/dev/null
done

echo ""
echo "[+] Operation complete."
echo "[!] REMINDER: DO NOT move or edit the original flag file! (Rule #10)"