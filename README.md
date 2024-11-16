# Overview❗

In this Problem, we focus on Access Control of the system. This refers to who has access to what functions. I user a combination of MAC and RBAC to enforce access control. This was in the form of an enum, which contains all permissions of the system. These permissions are then distributed to each "Role"/User to allow them various access to justInvest systems (though this is _not_ implemented yet)

## How To Run ⚠️

You can run either the main.py, or test.py. The main contains some basic tests. These were initial tests to create each "Role" (User) and to see if they had their permissions. Better, more thorough tests, were included later in development which can be found in the "test.py" 

On the VM, you can run either by: 

```bash
python3 main.py
```

```bash
python3  test.py
```

The above assumes that you are in the project directory (wherever the above two files are)


## License
The justInvest System is released under the [MIT License](https://opensource.org/licenses/MIT).