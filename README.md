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
pip install -r req.txt
```
For python3
```
pip3 install -r req.txt
```

Better to create a virtualenv environment for the tool. Please note that using sudo with pip is not recommended.

## Author

* **Mohammed Aldoub**, also known as **Voulnet**, find me on [Twitter](https://www.twitter.com/Voulnet)


## Contributing

PRs are welcome!

### Help

- From outside (in the terminal), run it with -help.
- From inside the tool, run **help** to see each menu's command options.
