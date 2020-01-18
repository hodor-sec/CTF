#!/bin/bash

# Refer to the logfile as argument value
LOGFILE=$1

# Declare an array of desired filters
declare -a filter=(
uri
host
user_agent
username
ts
uid
id.orig_h
id.orig_p
id.resp_h
id.resp_p
trans_depth
method
host
uri
referrer
version
user_agent
origin
request_body_len
response_body_len
status_code
status_msg
info_code
info_msg
tags
username
password
proxied
orig_fuids
orig_filenames
orig_mime_types
resp_fuids
resp_filenames
resp_mime_types
)

# Declare an array for the possible payloads
declare -a payload=(
"1=1"                   # SQLi
"1' "                   # SQLi
"UNION"                 # SQLi
"SELECT"                # SQLi
"<"                     # XSS
">"                     # XSS
"<script>"              # XSS
"\\\x"                  # Shellcode
"/etc/passwd"           # LFI
"../"                   # LFI
":;"                    # Shellshock
)

# Do a nested loop for the variables
for filt in ${filter[@]}; do
    for payl in ${payload[@]}; do
        cat $LOGFILE | jq -r '.[] | select(.'${filt}' | contains('\"${payl}\"')) | ."id.orig_h"'        # Based on host IP
    done
done
