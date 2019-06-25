![Logo of barq](https://raw.githubusercontent.com/Voulnet/barq/master/logo.png)

# barq
barq: The AWS Cloud Post Exploitation framework!

## What is it?

barq is a post-exploitation framework that allows you to easily perform attacks on a running AWS infrastructure. It allows you to attack running EC2 instances without having the original instance SSH keypairs. It also allows you to perform enumeration and extraction of stored Secrets and Parameters in AWS.

## Prerequisites

- An existing AWS account access key id and secret (Token too in some case) 
- Python 2 or 3. It can run with both.
To run the msfvenom payloads, you need msfvenom to be available on your workstation, with the PATH setup correctly.

## Installing

For python 2:
```
pip install -r requirements.txt
```
For python3
```
pip3 install -r requirements.txt
```

Better to create a virtualenv environment for the tool. Please note that using sudo with pip is not recommended.

## Author

* **Mohammed Aldoub**, also known as **Voulnet**, find me on [Twitter](https://www.twitter.com/Voulnet)

## Main Features

- Attacking EC2 instances without knowing keypairs or connection profiles/passwords.
- Dumping EC2 secrets and parameters.
- Enumerating EC2 instances and security groups.
- Ability to launch Metasploit and Empire payloads against EC2 instances.
- Training mode to test attacks and features without messing with running production environment.
- Tab-completed commands in a menu-based navigation system.
- Ability to dump EC2 instance metadata details.
- Ability to use EC2 keys or tokens (for example acquired from compromised instances or leaked source code)
- Printing for you the listening commands for msfconsole in cli mode for easy copy-pasting.

## Contributing

PRs are welcome!

### TODO:

- Create a plugin-based class system for menus in the framework
- Add a feature to exclude attacker-defined IPs and ports from security groups.
- Add persistence functionality.
- Launch attacks against Lambda, S3 and RDS.
- Export hostnames, IPs and ports in an nmap-ready format for scanning.
- Integrate fully with Metasploit and Empire REST APIs.

## Help

- From outside (in the terminal), run it with -help.
- From inside the tool, run **help** to see each menu's command options.

## Questions?

- Raise an issue here in Github.
- Contact me on Twitter.
