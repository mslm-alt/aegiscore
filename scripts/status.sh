#!/bin/bash
# AegisCore anlık status — çalışan process'e USR1 gönder
PID_FILE="$(dirname "$0")/../data/aegiscore.pid"
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "AegisCore PID=$PID — status isteniyor..."
        kill -USR1 "$PID"
    else
        echo "Hata: PID=$PID artık çalışmıyor."
    fi
else
    echo "Hata: $PID_FILE bulunamadı. AegisCore çalışıyor mu?"
fi
