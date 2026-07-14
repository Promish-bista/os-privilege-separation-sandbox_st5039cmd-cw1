# ST5039CMD Programming and Operating Systems — Coursework 1

**Module:** Programming and Operating Systems (ST5039CMD)
**Assignment:** CW1 (Regular), March Intake 2026

This repository contains the source code, test evidence, and supporting
documentation for both tasks in this coursework.

## Repository structure
.
    ├── task1/                Privilege separation in password validation
    │   ├── backend.c         Privileged process: validates credentials, drops root
    │   ├── frontend.c        Unprivileged process: collects user input
    │   └── evidence/         Logs and test output supporting investigation answers
    ├── task2/                User space malware analysis sandbox (added separately)
    └── README.md
## Task 1: Privilege Separation in Password Validation

### Overview

Two independent processes, communicating over a UNIX domain socket:

- frontend.c runs as a normal, unprivileged user. Its only job is to
  collect a username and password and send them to the backend. It
  never touches the credential store and never runs with elevated
  privilege.

- backend.c starts with root privilege (required to read the protected
  credential store), performs the one privileged operation it needs
  (reading a password hash and verifying it with crypt()), then
  immediately and permanently drops privileges using setresuid() and
  setresgid() before doing anything else, including before sending the
  result back to the frontend.

This demonstrates the principle of least privilege enforced at the
operating-system level via process isolation, rather than in-process
logic.

### How to build and run

Requires a Linux system with gcc and libcrypt-dev.

    cd task1
    gcc -Wall -o backend backend.c -lcrypt
    gcc -Wall -o frontend frontend.c

One-time setup (creates the unprivileged service account and a
protected test credential file that stands in for /etc/shadow):

    sudo useradd -r -s /usr/sbin/nologin authsvc
    mkpasswd -m sha-512 "TestPass123"
    echo 'alice:<paste hash here>' | sudo tee /etc/myshadow.txt
    sudo chown root:root /etc/myshadow.txt
    sudo chmod 600 /etc/myshadow.txt

Running it (two terminals):

    # Terminal 1 - backend needs root to read the protected credential file
    sudo ./backend

    # Terminal 2 - frontend runs as a normal user
    ./frontend
    # Username: alice
    # Password: TestPass123

### Evidence

The evidence/ folder contains captured terminal output for:

| File | What it demonstrates |
|---|---|
| backend_pass_run.log / frontend_pass_run.log | Successful authentication end-to-end |
| backend_fail_run.log / frontend_fail_run.log | Correct rejection of a wrong password |
| frontend_cannot_read_shadow.log | The unprivileged frontend process cannot read the credential file directly - proof that privilege separation actually restricts access |
| proc_status_after_drop.log | External, kernel-level verification via /proc/pid/status, showing all four UID fields (real, effective, saved, filesystem) changed to the unprivileged user after the drop - independent of the program's own self-reported claim |
| attack_malformed_input.log | Backend safely rejects a request with no valid username:password structure |
| attack_empty_connection.log | Backend safely handles a connection that closes with zero bytes sent |
| attack_nonexistent_user.log | Backend correctly rejects a username not present in the credential store, and still drops privileges unconditionally regardless of authentication outcome |
## Task 2: User Space Malware Analysis Sandbox

(To be added.)

## Author

Coventry University / Softwarica College of IT & E-Commerce
Module: ST5039CMD Programming and Operating Systems
