#!/usr/bin/env python3
"""
Velociraptor Launcher
A user-friendly interface for running Velociraptor reconnaissance tool
"""

import sys
import os
import argparse
import json
from pathlib import Path

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from velociraptor import Velociraptor

def print_banner():
    """Print Velociraptor banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗
    ║                                                                                                   ║
    ║  ██╗   ██╗███████╗██╗      ██████╗  ██████╗██╗██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗   ║
    ║  ██║   ██║██╔════╝██║     ██╔═══██╗██╔════╝██║██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗  ║
    ║  ██║   ██║█████╗  ██║     ██║   ██║██║     ██║██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝  ║
    ║  ╚██╗ ██╔╝██╔══╝  ██║     ██║   ██║██║     ██║██╔══██╗██╔══██║██╔═══╝    ██║   ██║   ██║██╔══██╗  ║
    ║   ╚████╔╝ ███████╗███████╗╚██████╔╝╚██████╗██║██║  ██║██║  ██║██║        ██║   ╚██████╔╝██║  ██║  ║
    ║    ╚═══╝  ╚══════╝╚══════╝ ╚═════╝  ╚═════╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝  ║
    ║                                                                                                   ║
    ║                                 ⚡ Automated Penetration Testing Tool ⚡                          ║
    ║                                                                                                   ║
    ║                       🦖 Enumeration  🔍 Port Scanning  🛡️  Vulnerability Assessment                 ║
    ║                        🌐 Web App Testing  🔧 Exploitation  📊 Reporting & Analysis                  ║
    ║                                                                                                   ║
    ║                            Version: 1.0.0  |  Author: Rock  |  License: MIT                       ║
    ║                                                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def load_config(config_file="config.json"):
    """Load configuration from file."""
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"⚠️  Error parsing {config_file}, using default configuration")
    return {}

def save_config(config, config_file="config.json"):
    """Save configuration to file."""
    try:
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=4)
        print(f"✅ Configuration saved to {config_file}")
    except Exception as e:
        print(f"❌ Error saving configuration: {e}")

def interactive_mode():
    """Run Velociraptor in interactive mode."""
    print("🦖 Welcome to Velociraptor!")
    print("=" * 50)
    
    # Get target domain
    target = input("Enter target domain (e.g., example.com): ").strip()
    if not target:
        print("❌ No target domain provided. Exiting.")
        return
    
    # Validate domain
    if '.' not in target:
        print("❌ Invalid domain format. Please include the TLD (e.g., .com)")
        return
    
    # Create Velociraptor instance
    velociraptor = Velociraptor(target)
    
    # Show available options
    print("\n📋 Available reconnaissance tasks:")
    print("1.  Full reconnaissance (all tasks)")
    print("2.  Subdomain enumeration")
    print("3.  Port scanning")
    print("4.  Vulnerability scanning")
    print("5.  Web application testing")
    print("6.  Custom task selection")
    print("7.  Configuration")
    print("8.  Exit")
    
    while True:
        choice = input("\nSelect an option (1-8): ").strip()
        
        if choice == "1":
            print("\n🚀 Starting full reconnaissance...")
            velociraptor.run_full_recon()
            break
            
        elif choice == "2":
            print("\n🔍 Running subdomain enumeration...")
            velociraptor.create_folder_structure()
            velociraptor.subdomain_enumeration()
            break
            
        elif choice == "3":
            print("\n🔍 Running port scanning...")
            velociraptor.create_folder_structure()
            velociraptor.port_scanning()
            break
            
        elif choice == "4":
            print("\n🔍 Running vulnerability scanning...")
            velociraptor.create_folder_structure()
            velociraptor.vulnerability_scanning()
            break
            
        elif choice == "5":
            print("\n🔍 Running web application testing...")
            velociraptor.create_folder_structure()
            velociraptor.directory_bruteforce()
            velociraptor.xss_detection()
            velociraptor.sql_injection()
            velociraptor.security_headers_check()
            break
            
        elif choice == "6":
            custom_task_selection(velociraptor)
            break
            
        elif choice == "7":
            configuration_menu()
            continue
            
        elif choice == "8":
            print("👋 Goodbye!")
            return
            
        else:
            print("❌ Invalid choice. Please select 1-8.")

def custom_task_selection(velociraptor):
    """Allow user to select custom tasks."""
    print("\n📋 Select tasks to run:")
    
    tasks = [
        ("Subdomain Enumeration", velociraptor.subdomain_enumeration),
        ("Port Scanning", velociraptor.port_scanning),
        ("Screenshot Capture", velociraptor.screenshot_capture),
        ("Directory Brute-Forcing", velociraptor.directory_bruteforce),
        ("JavaScript Analysis", velociraptor.javascript_analysis),
        ("Parameter Discovery", velociraptor.parameter_discovery),
        ("XSS Detection", velociraptor.xss_detection),
        ("SQL Injection", velociraptor.sql_injection),
        ("SSRF Discovery", velociraptor.ssrf_discovery),
        ("LFI/RFI Detection", velociraptor.lfi_rfi_detection),
        ("Open Redirect Detection", velociraptor.open_redirect_detection),
        ("Security Headers Check", velociraptor.security_headers_check),
        ("API Reconnaissance", velociraptor.api_recon),
        ("Content Discovery", velociraptor.content_discovery),
        ("S3 Bucket Enumeration", velociraptor.s3_bucket_enumeration),
        ("CMS Enumeration", velociraptor.cms_enumeration),
        ("WAF Detection", velociraptor.waf_detection),
        ("Information Disclosure", velociraptor.information_disclosure),
        ("Reverse Shell Generation", velociraptor.reverse_shell_generation),
        ("Mass Exploitation", velociraptor.mass_exploitation),
        ("Vulnerability Scanning", velociraptor.vulnerability_scanning),
        ("Subdomain Takeover", velociraptor.subdomain_takeover),
        ("Endpoint Analysis", velociraptor.endpoint_analysis),
        ("Technology Detection", velociraptor.technology_detection)
    ]
    
    for i, (task_name, _) in enumerate(tasks, 1):
        print(f"{i:2d}. {task_name}")
    
    print("0.  Run all selected tasks")
    print("99. Cancel")
    
    selected_tasks = []
    
    while True:
        choice = input("\nSelect task number (or 0 to run, 99 to cancel): ").strip()
        
        if choice == "0":
            if selected_tasks:
                print(f"\n🚀 Running {len(selected_tasks)} selected tasks...")
                velociraptor.create_folder_structure()
                
                for task_name, task_func in selected_tasks:
                    print(f"🔍 Running {task_name}...")
                    try:
                        task_func()
                        print(f"✅ {task_name} completed")
                    except Exception as e:
                        print(f"❌ {task_name} failed: {e}")
                
                velociraptor.generate_final_report()
                print(f"\n🎉 Custom reconnaissance completed!")
                print(f"📁 Results saved in: {velociraptor.base_dir}")
            else:
                print("❌ No tasks selected.")
            break
            
        elif choice == "99":
            print("❌ Cancelled.")
            return
            
        else:
            try:
                task_index = int(choice) - 1
                if 0 <= task_index < len(tasks):
                    task_name, task_func = tasks[task_index]
                    if (task_name, task_func) not in selected_tasks:
                        selected_tasks.append((task_name, task_func))
                        print(f"✅ Added: {task_name}")
                    else:
                        selected_tasks.remove((task_name, task_func))
                        print(f"❌ Removed: {task_name}")
                else:
                    print("❌ Invalid task number.")
            except ValueError:
                print("❌ Invalid input. Please enter a number.")

def configuration_menu():
    """Configuration menu."""
    print("\n⚙️  Configuration Menu:")
    print("1. View current configuration")
    print("2. Edit configuration")
    print("3. Reset to defaults")
    print("4. Back to main menu")
    
    choice = input("Select option (1-4): ").strip()
    
    if choice == "1":
        config = load_config()
        if config:
            print("\n📋 Current Configuration:")
            print(json.dumps(config, indent=2))
        else:
            print("📋 No configuration file found.")
    
    elif choice == "2":
        print("⚠️  Configuration editing not implemented yet.")
        print("   Edit config.json manually for now.")
    
    elif choice == "3":
        confirm = input("Are you sure you want to reset configuration? (y/N): ").strip()
        if confirm.lower() == 'y':
            # Create default config
            default_config = {
                "general": {
                    "timeout": 300,
                    "threads": 10,
                    "verbose": True
                }
            }
            save_config(default_config)
    
    elif choice == "4":
        return
    
    else:
        print("❌ Invalid choice.")

def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Velociraptor - Automated Penetration Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 launch.py -t example.com                    # Run full recon
  python3 launch.py -t example.com -m interactive     # Interactive mode
  python3 launch.py -t example.com -s subdomain       # Run specific task
  python3 launch.py --config                          # Configuration menu
        """
    )
    
    parser.add_argument(
        "-t", "--target",
        help="Target domain (e.g., example.com)"
    )
    
    parser.add_argument(
        "-m", "--mode",
        choices=["full", "interactive", "custom"],
        default="full",
        help="Operation mode (default: full)"
    )
    
    parser.add_argument(
        "-s", "--task",
        help="Run specific task (e.g., subdomain, portscan, vulnscan)"
    )
    
    parser.add_argument(
        "--config",
        action="store_true",
        help="Open configuration menu"
    )
    
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Hide banner"
    )
    
    args = parser.parse_args()
    
    if not args.no_banner:
        print_banner()
    
    # Configuration menu
    if args.config:
        configuration_menu()
        return
    
    # Interactive mode
    if args.mode == "interactive" or not args.target:
        interactive_mode()
        return
    
    # Command line mode
    if args.target:
        velociraptor = Velociraptor(args.target)
        
        if args.task:
            # Run specific task
            task_mapping = {
                "subdomain": velociraptor.subdomain_enumeration,
                "portscan": velociraptor.port_scanning,
                "vulnscan": velociraptor.vulnerability_scanning,
                "xss": velociraptor.xss_detection,
                "sqli": velociraptor.sql_injection,
                "headers": velociraptor.security_headers_check,
                "tech": velociraptor.technology_detection
            }
            
            if args.task in task_mapping:
                print(f"🔍 Running {args.task} on {args.target}...")
                velociraptor.create_folder_structure()
                task_mapping[args.task]()
                velociraptor.generate_final_report()
                print(f"✅ Task completed! Results in: {velociraptor.base_dir}")
            else:
                print(f"❌ Unknown task: {args.task}")
                print(f"Available tasks: {', '.join(task_mapping.keys())}")
        else:
            # Run full reconnaissance
            print(f"🚀 Starting full reconnaissance on {args.target}...")
            velociraptor.run_full_recon()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user. Exiting...")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1) 