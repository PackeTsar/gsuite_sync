# GSuite_Sync
Sync MAC addresses from your GSuite into Cisco ISE

[![Build Status](https://travis-ci.org/PackeTsar/gsuite_sync.svg?branch=master)](https://travis-ci.org/PackeTsar/gsuite_sync)




-----------------------------------------
#   INSTALL PROCESS   ###
To set up gsync as a service on Linux, follow the below process


### Prep the Linux OS with Python3
1. Install required OS packages for Python
  - **Raspberry Pi** may need Python and PIP `sudo apt install -y python-pip` as well as `sudo apt-get install libffi-dev`
  - **Debian (Ubuntu)** distributions may need Python and PIP
    - Install Python and PIP: `sudo apt install -y python-pip`
  - **RHEL (CentOS)** distributions usually need PIP
    - Install the EPEL package: `sudo yum install -y epel-release`
    - Install PIP: `sudo yum install -y python36-pip`
    - Back up the old Python2 binary: `mv /usr/bin/python /usr/bin/python-old`
    - Make Python3 the default binary: `sudo ln -fs /usr/bin/python36 /usr/bin/python`


### Install GSync from PyPi
1. Install using PIP: `pip install gsuite_sync`


### Install GSync from source
1. Retrieve the source code repository using one of the two below methods
  - **Method #1**: Install a Git client (process differs depending on OS) and clone the GSuite_Sync repository using Git `git clone https://github.com/PackeTsar/gsuite_sync.git`
    - Change to the branch you want to install using `git checkout <branch_name>`
  - **Method #2**: Download and extract the repository files from the [Github Repo](https://github.com/PackeTsar/gsuite_sync)
    - Make sure to download the branch you want to install
2. Move into the gsuite_sync project directory `cd gsuite_sync`
3. Run the setup.py file to build the package into the ./build/ directory `python setup.py build`
4. Use PIP to install the package `pip install .`
5. Once the install completes, you should be able to run the command `gsync -h` and see the help menu. GSync is now ready to use.


### Help Output
```
usage: gsync [-h] [-v] [-gc CREDENTIAL_FILE] [-gm REGEX] [-ia IP/ADDRESS]
             [-iu USERNAME] [-ip PASSWORD] [-ig GROUP_NAME] [-c CONFIG_FILE]
             [-l LOG_FILE] [-d] [-fs] [-um MAC_ADDRESS] [-us SERIAL_NUMBER]
             [-m]

GSuite_Sync - Sync Chromebook MAC addresses from your GSuite into Cisco ISE

Misc Arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit

Required Arguments:
  -gc CREDENTIAL_FILE, --gsuite_credential CREDENTIAL_FILE
                        GSuite Credential File
  -ia IP/ADDRESS, --ise_address IP/ADDRESS
                        ISE DNS or IP Address
  -iu USERNAME, --ise_username USERNAME
                        ISE Login Username
  -ip PASSWORD, --ise_password PASSWORD
                        ISE Login Password
  -ig GROUP_NAME, --ise_group GROUP_NAME
                        ISE Target Endpoint Group

Optional Arguments:
  -gm REGEX, --gsuite_path_match REGEX
                        GSuite Object Path Match Pattern
  -c CONFIG_FILE, --config_file CONFIG_FILE
                        Config File Path
  -l LOG_FILE, --logfiles LOG_FILE
                        Log File Path
  -d, --debug           Set debug level (WARNING by default)
                                Debug level INFO:  '-d'
                                Debug level DEBUG: '-d'

Action Arguments:
  -fs, --full_sync      Perform full sync of GSuite MACs to ISE Group
  -um MAC_ADDRESS, --update_mac MAC_ADDRESS
                        Push an individual MAC to the ISE Group
  -us SERIAL_NUMBER, --update_serial SERIAL_NUMBER
                        Lookup a device's MAC and update it in the ISE Group
  -m, --maintain        maintain pushing devices
```

### Example Config Files
Arguments can be passed in at the command line or with a config file. It is often easier to use a config file and that is what we will do for setting up the service. The `/root/credentials.json` file referenced is an API credential file for your GSuite account.

#### Example Config File (/root/config.json)
```json
{
  "gsuite_credential": "/root/credentials.json",
  "gsuite_path_match": "SOMEREGEXPATHMATCH",
  "ise_address": "192.168.1.100",
  "ise_username": "admin",
  "ise_password": "admin123",
  "ise_group": "my_special_group",
  "logfiles": ["/etc/gsync/logs.log"]
}
```

### Create the Service File

Use VI to create a new file (`vi /etc/init.d/gsync`) and insert the below BASH script for the file contents

```sh
#!/bin/bash
# gsync daemon
# chkconfig: 345 20 80
# description: gsync Daemon
# processname: gsync

DAEMON_PATH="/usr/local/bin/"

DAEMON=gsync
STDOUTFILE=/etc/gsync/stdout.log
STDERR=/etc/gsync/stderr.log

NAME=gsync
DESC="gsync Daemon"
PIDFILE=/var/run/$NAME.pid
SCRIPTNAME=/etc/init.d/$NAME

case "$1" in
start)
        printf "%-50s" "Starting $NAME..."
        cd $DAEMON_PATH
        PID=`stdbuf -o0 $DAEMON -c /root/config.json -m >> $STDOUTFILE 2>>$STDERR & echo $!`
        #echo "Saving PID" $PID " to " $PIDFILE
        if [ -z $PID ]; then
            printf "%s
" "Fail"
        else
            echo $PID > $PIDFILE
            printf "%s
" "Ok"
        fi
;;
status)
        if [ -f $PIDFILE ]; then
            PID=`cat $PIDFILE`
            if [ -z "`ps axf | grep ${PID} | grep -v grep`" ]; then
                printf "%s
" "Process dead but pidfile exists"
            else
                echo "$DAEMON (pid $PID) is running..."
            fi
        else
            printf "%s
" "$DAEMON is stopped"
        fi
;;
stop)
        printf "%-50s" "Stopping $NAME"
            PID=`cat $PIDFILE`
            cd $DAEMON_PATH
        if [ -f $PIDFILE ]; then
            kill -HUP $PID
            printf "%s
" "Ok"
            rm -f $PIDFILE
        else
            printf "%s
" "pidfile not found"
        fi
;;

restart)
        $0 stop
        $0 start
;;

*)
        echo "Usage: $0 {status|start|stop|restart}"
        exit 1
esac

```



### Finish and Start Up Service
```
chmod 777 /etc/init.d/gsync
chkconfig gsync on
service gsync start
service gsync status
```
