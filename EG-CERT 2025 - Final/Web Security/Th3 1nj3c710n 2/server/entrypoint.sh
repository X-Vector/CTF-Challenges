#!/bin/bash

# Function to generate and write the flag
generate_flag() {
    RANDOM_HEX=$(openssl rand -hex 4)
    FLAG="EGCERT{rC3_v1a_51mpl3_f0rm4t_5tr1ng_${RANDOM_HEX}}"
    echo "$FLAG" > /tmp/flag_flag_flag.txt
    export FLAG="$FLAG"
    echo "[DEBUG] New FLAG generated: $FLAG"
}

# Ensure data dir exists
mkdir -p /app/data

# Start a background loop that updates the flag every 10 seconds
(
    while true; do
        generate_flag
        sleep 10
    done
) &

# Start the Flask app in foreground
exec python app.py
