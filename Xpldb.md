#!/bin/bash

# modules/exploitdb_30.sh



TARGET="$1"

OUTPUT_DIR="$2"

NMAP_FILE="$OUTPUT_DIR/nmap_30_comprehensive.txt"



# ============= EJEMPLO 1: Búsqueda básica por servicio =============

exploit_search_basic() {

    echo "[1] Búsqueda básica por software"

    searchsploit --colour -t "openssh" 2>/dev/null \

        > "$OUTPUT_DIR/exploit_01_basic.txt"

}



# ============= EJEMPLO 2: Búsqueda por versión exacta =============

exploit_search_exact_version() {

    echo "[2] Búsqueda versión exacta"

    searchsploit "Apache httpd 2.4.49" --json 2>/dev/null \

        > "$OUTPUT_DIR/exploit_02_exact.json"

}



# ============= EJEMPLO 3: Búsqueda por CVE =============

exploit_search_cve() {

    echo "[3] Búsqueda por CVE"

    for cve in "CVE-2021-44228" "CVE-2017-0144" "CVE-2019-0708" "CVE-2021-34527"; do

        searchsploit --cve "$cve" 2>/dev/null \

            >> "$OUTPUT_DIR/exploit_03_cve.txt"

    done

}



# ============= EJEMPLO 4: Filtro por tipo remote (RCE) =============

exploit_search_remote() {

    echo "[4] Exploits remotos"

    searchsploit --type remote --text "rce" 2>/dev/null \

        | head -50 > "$OUTPUT_DIR/exploit_04_remote.txt"

}



# ============= EJEMPLO 5: Filtro por tipo local (priv escalation) =============

exploit_search_local() {

    echo "[5] Exploits locales (priv esc)"

    searchsploit --type local --text "privilege" 2>/dev/null \

        | head -50 > "$OUTPUT_DIR/exploit_05_local.txt"

}



# ============= EJEMPLO 6: Filtro por plataforma Windows =============

exploit_search_windows() {

    echo "[6] Exploits Windows"

    searchsploit --platform windows --type remote 2>/dev/null \

        | head -100 > "$OUTPUT_DIR/exploit_06_windows.txt"

}



# ============= EJEMPLo 7: Filtro por plataforma Linux =============

exploit_search_linux() {

    echo "[7] Exploits Linux"

    searchsploit --platform linux --type remote 2>/dev/null \

        | head -100 > "$OUTPUT_DIR/exploit_07_linux.txt"

}



# ============= EJEMPLO 8: Webapps exploits =============

exploit_search_webapps() {

    echo "[8] Webapps exploits"

    searchsploit --type webapps --text "upload" 2>/dev/null \

        | head -50 > "$OUTPUT_DIR/exploit_08_webapps.txt"

}



# ============= EJEMPLO 9: Dos exploits =============

exploit_search_dos() {

    echo "[9] DoS exploits"

    searchsploit --type dos --text "denial" 2>/dev/null \

        | head -50 > "$OUTPUT_DIR/exploit_09_dos.txt"

}



# ============= EJEMPLO 10: Exploits de PHP =============

exploit_search_php() {

    echo "[10] PHP exploits"

    searchsploit "php" --type webapps 2>/dev/null \

        | head -50 > "$OUTPUT_DIR/exploit_10_php.txt"

}



# ============= EJEMPLO 11: Exploits de Apache =============

exploit_search_apache() {

    echo "[11] Apache exploits"

    searchsploit "apache" --type webapps 2>/dev/null \

        | head -50 > "$OUTPUT_DIR/exploit_11_apache.txt"

}



# ============= EJEMPLO 12: Exploits de Nginx =============

exploit_search_nginx() {

    echo "[12] Nginx exploits"

    searchsploit "nginx" 2>/dev/null \

        | head -50 > "$OUTPUT_DIR/exploit_12_nginx.txt"

}



# ============= EJEMPLO 13: Exploits SMB específicos =============

exploit_search_smb() {

    echo "[13] SMB exploits"

    searchsploit "smb" --type remote 2>/dev/null \

        | head -30 > "$OUTPUT_DIR/exploit_13_smb.txt"

}



# ============= EJEMPLO 14: Exploits SSH específicos =============

exploit_search_ssh() {

    echo "[14] SSH exploits"

    searchsploit "openssh" --type remote 2>/dev/null \

        | head -30 > "$OUTPUT_DIR/exploit_14_ssh.txt"

}



# ============= EJEMPLO 15: Exploits RDP específicos =============

exploit_search_rdp() {

    echo "[15] RDP exploits"

    searchsploit "rdp" --type remote 2>/dev/null \

        | head -30 > "$OUTPUT_DIR/exploit_15_rdp.txt"

}



# ============= EJEMPLO 16: Exploits MySQL =============

exploit_search_mysql() {

    echo "[16] MySQL exploits"

    searchsploit "mysql" --type remote 2>/dev/null \

        | head -30 > "$OUTPUT_DIR/exploit_16_mysql.txt"

}



# ============= EJEMPLO 17: Exploits WordPress =============

exploit_search_wordpress() {

    echo "[17] WordPress exploits"

    searchsploit "wordpress" --type webapps 2>/dev/null \

        | head -50 > "$OUTPUT_DIR/exploit_17_wordpress.txt"

}



# ============= EJEMPLO 18: Exploits Drupal =============

exploit_search_drupal() {

    echo "[18] Drupal exploits"

    searchsploit "drupal" --type webapps 2>/dev/null \

        | head -50 > "$OUTPUT_DIR/exploit_18_drupal.txt"

}



# ============= EJEMPLO 19: Exploits de CMS varios =============

exploit_search_cms() {

    echo "[19] CMS exploits múltiples"

    for cms in joomla magento typo3 umbraco phpmyadmin moodle; do

        searchsploit "$cms" --type webapps 2>/dev/null \

            | head -20 >> "$OUTPUT_DIR/exploit_19_cms.txt"

        echo "--- $cms ---" >> "$OUTPUT_DIR/exploit_19_cms.txt"

    done

}



# ============= EJEMPLO 20: Exploits por puerto detectado =============

exploit_search_by_port() {

    echo "[20] Auto-búsqueda por puerto"

    > "$OUTPUT_DIR/exploit_20_by_port.txt"

    grep -oP '^\d+/\w+\s+\w+' "$NMAP_FILE" 2>/dev/null | \

        awk '{print \$2}' | sort -u | head -20 | while read -r service; do

        searchsploit "\$service" --type remote 2>/dev/null | head -10 \

            >> "$OUTPUT_DIR/exploit_20_by_port.txt"

    done

}



# ============= EJEMPLO 21: Output en formato JSON =============

exploit_format_json() {

    echo "[21] JSON output para parsing"

    searchsploit --json -t "linux kernel" 2>/dev/null \

        > "$OUTPUT_DIR/exploit_21.json"

}



# ============= EJEMPLO 22: Mirror (descargar) exploits relevantes =============

exploit_mirror_download() {

    echo "[22] Descargando exploits relevantes"

    mkdir -p "$OUTPUT_DIR/exploits_mirrored"

    

    # Top CVEs críticos

    for cve in "CVE-2021-44228" "CVE-2021-26855" "CVE-2019-0708"; do

        searchsploit --cve "$cve" --json 2>/dev/null | \

            python3 -c "

import json, sys

try:

    data = json.load(sys.stdin)

    for exploit in data.get('RESULTS', [])[:2]:

        print(f\"{exploit['EDB-ID']}|{exploit['Path']}\")

except: pass

" 2>/dev/null | while IFS='|' read -r edb_id path; do

            [ -n "$edb_id" ] && searchsploit -m "$edb_id" -w "$OUTPUT_DIR/exploits_mirrored/" 2>/dev/null

        done

    done

}



# ============= EJEMPLO 23: Búsqueda por EDB-ID específico =============

exploit_search_by_edbid() {

    echo "[23] Búsqueda por EDB-ID"

    searchsploit "EDB-ID:49763" 2>/dev/null \

        > "$OUTPUT_DIR/exploit_23_edbid.txt"

}



# ============= EJEMPLO 24: Búsqueda por múltiples keywords =============

exploit_search_multi() {

    echo "[24] Búsqueda multi-keyword"

    searchsploit "openssh openssl rce" 2>/dev/null \

        > "$OUTPUT_DIR/exploit_24_multi.txt"

}



# ============= EJEMPLO 25: Exploits con título específico =============

exploit_search_title() {

    echo "[25] Búsqueda por título"

    searchsploit -t "remote code execution" 2>/dev/null \

        | head -50 > "$OUTPUT_DIR/exploit_25_title.txt"

}



# ============= EJEMPLO 26: Filtrar por año y plataforma =============

exploit_search_year() {

    echo "[26] Filtro por año"

    # searchsploit no soporta año directamente, pero podemos parsear

    searchsploit --platform windows --type remote 2>/dev/null | \

        grep -E "2020|2021|2022|2023|2024" | head -50 \

        > "$OUTPUT_DIR/exploit_26_recent.txt"

}



# ============= EJEMPLO 27: Análisis completo de Nmap =============

exploit_nmap_correlation() {

    echo "[27] Correlación Nmap -> ExploitDB"

    > "$OUTPUT_DIR/exploit_27_nmap_correlation.txt"

    

    # Extraer software y versiones

    grep -E "^\| |^[0-9]+/" "$NMAP_FILE" 2>/dev/null | \

        grep -oP '\b[A-Za-z][A-Za-z0-9_\-]+(\s+[\d.]+)?' | sort -u | while read -r entry; do

        if [ -n "$entry" ] && [ ${#entry} -gt 3 ]; then

            result=$(searchsploit "$entry" 2>/dev/null | head -5)

            if [ -n "$result" ]; then

                echo "=== $entry ===" >> "$OUTPUT_DIR/exploit_27_nmap_correlation.txt"

                echo "$result" >> "$OUTPUT_DIR/exploit_27_nmap_correlation.txt"

            fi

        fi

    done

}



# ============= EJEMPLO 28: Exploits Shellcode =============

exploit_search_shellcode() {

    echo "[28] Shellcodes disponibles"

    searchsploit --type shellcode --platform linux --arch x86 2>/dev/null \

        | head -50 > "$OUTPUT_DIR/exploit_28_shellcode.txt"

}



# ============= EJEMPLO 29: Exploits para IoT/Embedded =============

exploit_search_iot() {

    echo "[29] Exploits IoT/Embedded"

    searchsploit "router" "camera" "iot" 2>/dev/null \

        | head -50 > "$OUTPUT_DIR/exploit_29_iot.txt"

}



# ============= EJEMPLO 30: Auto-exploit basado en findings =============

exploit_auto_action() {

    echo "[30] Auto-acción sobre findings relevantes"

    

    # Buscar exploits de EternalBlue (si SMB está abierto)

    if nc -z "$TARGET" 445 2>/dev/null; then

        echo "[!] SMB abierto - revisando EternalBlue..."

        searchsploit --cve "CVE-2017-0144" --json 2>/dev/null \

            > "$OUTPUT_DIR/exploit_30_eternalblue.json"

    fi

    

    # Buscar exploits SSH (si SSH está abierto)

    if nc -z "$TARGET" 22 2>/dev/null; then

        echo "[!] SSH abierto - buscando exploits SSH..."

        searchsploit "openssh" --type remote 2>/dev/null | head -10 \

            > "$OUTPUT_DIR/exploit_30_ssh.txt"

    fi

    

    # Buscar exploits HTTP (si HTTP está abierto)

    if nc -z "$TARGET" 80 2>/dev/null; then

        echo "[!] HTTP abierto - buscando webapp exploits..."

        searchsploit --type webapps 2>/dev/null | head -20 \

            > "$OUTPUT_DIR/exploit_30_webapp.txt"

    fi

    

    # Buscar exploits para SMBGhost (más reciente)

    searchsploit --cve "CVE-2020-0796" --json 2>/dev/null \

        > "$OUTPUT_DIR/exploit_30_smbghost.json" 2>/dev/null &

    

    # Buscar ProxyLogon

    searchsploit --cve "CVE-2021-26855" --json 2>/dev/null \

        > "$OUTPUT_DIR/exploit_30_proxylogon.json" 2>/dev/null &

    

    wait

}



# Función principal

exploitdb_all_30() {

    exploit_search_basic

    exploit_search_exact_version

    exploit_search_cve

    exploit_search_remote

    exploit_search_local

    exploit_search_windows

    exploit_search_linux

    exploit_search_webapps

    exploit_search_dos

    exploit_search_php

    exploit_search_apache

    exploit_search_nginx

    exploit_search_smb

    exploit_search_ssh

    exploit_search_rdp

    exploit_search_mysql

    exploit_search_wordpress

    exploit_search_drupal

    exploit_search_cms

    exploit_search_by_port

    exploit_format_json

    exploit_mirror_download

    exploit_search_by_edbid

    exploit_search_multi

    exploit_search_title

    exploit_search_year

    exploit_nmap_correlation

    exploit_search_shellcode

    exploit_search_iot

    exploit_auto_action

}



