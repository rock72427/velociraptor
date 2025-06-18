#!/usr/bin/env python3
"""
Script to remove unwanted tools from Velociraptor configuration
"""

import re

# Tools to remove
tools_to_remove = [
    'xsstrike',
    'subjack', 
    'paramspider',
    'lfisuite',
    'kiterunner',
    'gopherus',
    'gitdumper',
    'fimap',
    'aquatone',
    'cmseek',
    'gf-patterns'
]

def update_velociraptor_py():
    """Remove unwanted tools from velociraptor.py"""
    print("Updating velociraptor.py...")
    
    with open('velociraptor.py', 'r') as f:
        content = f.read()
    
    # Remove tool definitions from required_tools dictionary
    for tool in tools_to_remove:
        # Find and remove the tool definition block
        pattern = rf"'{tool}':\s*{{[^}}]+}},?\s*"
        content = re.sub(pattern, '', content, flags=re.MULTILINE | re.DOTALL)
    
    # Clean up any trailing commas
    content = re.sub(r',\s*}', '}', content)
    
    with open('velociraptor.py', 'w') as f:
        f.write(content)
    
    print("✅ Updated velociraptor.py")

def update_config_json():
    """Remove unwanted tools from config.json"""
    print("Updating config.json...")
    
    import json
    
    with open('config.json', 'r') as f:
        config = json.load(f)
    
    # Remove tools from config
    for tool in tools_to_remove:
        if tool in config.get('tools', {}):
            del config['tools'][tool]
    
    with open('config.json', 'w') as f:
        json.dump(config, f, indent=4)
    
    print("✅ Updated config.json")

if __name__ == "__main__":
    print("Removing unwanted tools from Velociraptor configuration...")
    print(f"Tools to remove: {', '.join(tools_to_remove)}")
    print()
    
    update_velociraptor_py()
    update_config_json()
    
    print()
    print("✅ Configuration update completed!")
    print("The following tools have been removed from Velociraptor:")
    for tool in tools_to_remove:
        print(f"• {tool}") 