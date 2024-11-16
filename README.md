# Overview

In this problem, we focus on implementing a password file to save information about the user (passwords, username  etc.) The password file is a text file called `passwd.txt` (this should not be immidiately visible, only upon creating users should the file be made [obviously]). 

## Security 🔒
The user information is secured using `bcrypt` which incorporates automatic salting. More detail about the security can be seen in the `Password Manager` function in the main.py. Insight into the system will not be avaiable at the end of deployment (whitebox for now).

## How To Run ⚠️

You can run either the main.py, or test.py. The main contains a test user (that I used during testing _duh_). The test.py is probably more insightful as it provides more context as to what was implemented. 

On the VM, you can run either by:

```bash
python3 main.py
```

```bash
python3  test.py
```
The above assumes that you are in the project directory (wherever the above two files are)