# Bitwarden SSH Agent

A CLI utility that extracts SSH keys from your Bitwarden vault and adds them to your SSH agent.

![Demo](cast.svg)

## Prerequisites

- Python 3.7+
- Bitwarden CLI (`bw`) installed and configured
- SSH agent running on your system

## Installation

1. Clone this repository
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Make sure you're logged into Bitwarden CLI:
   ```bash
   bw login
   ```

2. Run the utility:
   ```bash
   python bw_ssh_agent.py
   ```

### Options

- `--dry-run`: Preview which keys would be added without actually adding them
- `--verbose`: Enable verbose logging
- `--filter TEXT`: Filter SSH keys by name or folder
- `--help`: Show help message and exit

## How it works

The utility performs the following steps:
1. Verifies Bitwarden CLI and SSH agent are available
2. Authenticates with Bitwarden (or uses existing session)
3. Retrieves SSH keys from your vault
4. Adds each key to your SSH agent

## Security Note

This utility handles sensitive SSH key data. It:
- Never stores SSH keys on disk
- Processes keys in memory only
- Uses secure methods to pass keys to ssh-agent