#!/usr/bin/env python3

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional, Dict

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live
from rich import print as rprint

console = Console()

class BitwardenSSHAgent:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.session_key = None
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=Console(),
            transient=True,
            expand=True
        )
        self.live = Live(self.progress, console=console, refresh_per_second=10)
        self.task_id = None

    def log(self, message: str, level: str = "info") -> None:
        """Log messages if verbose mode is enabled."""
        if self.verbose:
            if level == "error":
                console.print(f"[red]ERROR: {message}[/red]")
            elif level == "warning":
                console.print(f"[yellow]WARNING: {message}[/yellow]")
            else:
                console.print(f"[green]INFO: {message}[/green]")

    def start_progress(self, total_steps: int, description: str = "Processing"):
        """Start the progress bar."""
        self.live.start()
        self.task_id = self.progress.add_task(description, total=total_steps)

    def update_progress(self, advance: int = 1, description: Optional[str] = None):
        """Update the progress bar."""
        if description:
            self.progress.update(self.task_id, description=description)
        self.progress.update(self.task_id, advance=advance)

    def stop_progress(self):
        """Stop the progress bar."""
        self.progress.remove_task(self.task_id)
        self.live.stop()

    def check_prerequisites(self) -> bool:
        """Check if required tools are available."""
        try:
            # Check bw CLI
            subprocess.run(["bw", "--version"], capture_output=True, check=True)
            self.log("Bitwarden CLI is available")

            # Check ssh-agent
            
            if not os.environ.get("SSH_AUTH_SOCK") or not os.path.exists(os.environ.get("SSH_AUTH_SOCK")):
                self.log("SSH agent is not running, attempting to start it", "warning")
                # Start ssh-agent and get its environment variables
                result = subprocess.run(
                    ["ssh-agent", "-s"],
                    capture_output=True,
                    text=True
                )
                if result.returncode != 0:
                    raise Exception("Failed to start ssh-agent")
                
                # Parse and set environment variables
                for line in result.stdout.splitlines():
                    
                    if line.startswith("SSH_AUTH_SOCK=") or line.startswith("SSH_AGENT_PID="):
                        key, value = line.split(";")[0].split("=")
                        os.environ[key] = value
                
                self.log("Successfully started SSH agent")
            else:
                self.log("SSH agent is running")

            return True
        except subprocess.CalledProcessError:
            console.print("[red]Error: Bitwarden CLI (bw) is not installed or not in PATH[/red]")
            return False
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")
            return False

    def get_session_key(self) -> Optional[str]:
        """Get Bitwarden session key."""
        try:
            # First check if BW_SESSION is already set
            existing_session = os.environ.get("BW_SESSION")
            if existing_session:
                self.log("Using existing session from BW_SESSION environment variable")
                # Verify the session is valid
                env = os.environ.copy()
                result = subprocess.run(
                    ["bw", "status"],
                    capture_output=True,
                    text=True,
                    env=env
                )

                status = json.loads(result.stdout)
                if status.get("status") == "unlocked":
                    self.session_key = existing_session
                    return self.session_key
                else:
                    self.log("Existing session is locked or invalid", "warning")

            # If we get here, we need to prompt for password
            self.log("No active session found, attempting to unlock", "warning")
            
            # Temporarily stop progress bar for password input
            was_progress_active = self.task_id is not None
            if was_progress_active:
                self.stop_progress()
            
            password = click.prompt("Enter your Bitwarden master password", hide_input=True, type=str)
            
            # Restart progress bar if it was active
            if was_progress_active:
                self.start_progress(total_steps=3, description="Getting session key...")
                self.update_progress(advance=1)  # Advance to maintain correct progress state
            
            # Use popen to handle password input
            process = subprocess.Popen(
                ["bw", "unlock", password, "--raw"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            output, error = process.communicate()
            
            if process.returncode != 0:
                raise Exception(f"Failed to unlock Bitwarden vault: {error}")
            
            self.session_key = output.strip()
            return self.session_key

        except Exception as e:
            console.print(f"[red]Error getting session key: {str(e)}[/red]")
            return None

    def get_ssh_keys(self, name_filter: Optional[str] = None) -> List[Dict]:
        """Retrieve SSH keys from Bitwarden vault."""
        if not self.session_key:
            raise Exception("No active Bitwarden session")

        try:
            env = os.environ.copy()
            env["BW_SESSION"] = self.session_key

            # List all items
            result = subprocess.run(
                ["bw", "list", "items"],
                capture_output=True,
                text=True,
                env=env
            )

            if result.returncode != 0:
                raise Exception("Failed to list Bitwarden items")

            items = json.loads(result.stdout)
            
            # Filter for SSH keys
            ssh_keys = []
            for item in items:
                if "sshKey" in item and item["sshKey"].get("privateKey"):
                    if name_filter and name_filter.lower() not in item["name"].lower():
                        continue
                    ssh_keys.append(item)

            self.log(f"Found {len(ssh_keys)} SSH keys in vault")
            return ssh_keys

        except Exception as e:
            console.print(f"[red]Error retrieving SSH keys: {str(e)}[/red]")
            return []

    def add_key_to_agent(self, key_data: Dict, key_name: str) -> bool:
        """Add an SSH key to the SSH agent."""
        temp_key_file = None
        try:
            # Add key to agent with environment variables
            env = os.environ.copy()
            result = subprocess.run(
                ["ssh-add", "-"],
                capture_output=True,
                text=True,
                env=env,
                input=key_data["sshKey"]["privateKey"]
            )
            
            if result.returncode != 0:
                raise Exception(f"ssh-add failed: {result.stderr}")
            
            self.log(f"Successfully added key: {key_name} (fingerprint: {key_data['sshKey'].get('keyFingerprint', 'unknown')})")
            return True

        except Exception as e:
            console.print(f"[red]Error adding key {key_name}: {str(e)}[/red]")
            return False
        finally:
            # Clean up the temporary file
            if temp_key_file and os.path.exists(temp_key_file.name):
                temp_key_file.close()
                os.unlink(temp_key_file.name)

@click.command()
@click.option("--verbose", is_flag=True, help="Enable verbose logging")
@click.option("--dry-run", is_flag=True, help="Show which keys would be added without adding them")
@click.option("--filter", "name_filter", help="Filter SSH keys by name")
def main(verbose: bool, dry_run: bool, name_filter: Optional[str]):
    """Extract SSH keys from Bitwarden and add them to ssh-agent."""
    agent = BitwardenSSHAgent(verbose=verbose)

    # Start progress
    agent.start_progress(total_steps=3, description="Checking prerequisites...")

    # Check prerequisites
    if not agent.check_prerequisites():
        agent.stop_progress()
        sys.exit(1)

    agent.update_progress(advance=1, description="Getting session key...")

    # Get session key
    if not agent.get_session_key():
        agent.stop_progress()
        sys.exit(1)

    agent.update_progress(advance=1, description="Retrieving SSH keys...")

    # Get SSH keys
    ssh_keys = agent.get_ssh_keys(name_filter)
    agent.stop_progress()
    
    if not ssh_keys:
        console.print("[yellow]No SSH keys found in vault[/yellow]")
        sys.exit(0)

    # Process keys
    if dry_run:
        console.print("\n[yellow]Dry run - would add these keys:[/yellow]")
        for key in ssh_keys:
            console.print(f"  • {key['name']} (fingerprint: {key['sshKey'].get('keyFingerprint', 'unknown')})")
    else:
        console.print("\n[green]Adding SSH keys to agent:[/green]")
        agent.start_progress(total_steps=len(ssh_keys), description="Adding SSH keys...")
        for key in ssh_keys:
            agent.update_progress(description=f"Adding key: {key['name']}")
            if agent.add_key_to_agent(key, key["name"]):
                console.print(f"  ✓ Added {key['name']} (fingerprint: {key['sshKey'].get('keyFingerprint', 'unknown')})")
            else:
                console.print(f"  ✗ Failed to add {key['name']}")
            agent.update_progress(advance=1)
        agent.stop_progress()

    if not dry_run:
        console.print("\n[green]Operation completed successfully![/green]")

if __name__ == "__main__":
    main() 
