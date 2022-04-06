# suspend_manager
Using pyshark to measure net usage to suspend a server.

Example:

````listening on eno1
Tue Apr  5 18:57:04 2022 source: x.x.x.x:5353 IP to: x.x.x.x UDP size: 110
Tue Apr  5 18:57:04 2022 source: x.x.x.x:50589 IP to: x.x.x.x TCP size: 74
Tue Apr  5 18:57:04 2022 source: x.x.x.x:52143 IP to: x.x.x.x TCP size: 74
Tue Apr  5 18:57:04 2022 source: x.x.x.x:46731 IP to: x.x.x.x TCP size: 74
Tue Apr  5 18:57:04 2022 source: x.x.x.x:45697 IP to: x.x.x.x TCP size: 74
Tue Apr  5 18:57:04 2022 source: x.x.x.x:33103 IP to: x.x.x.x TCP size: 74
eno1 is idle. Average packet size is: 349.9259259259259.
There are no known services running. We can suspend now.
rtcwake: wakeup from "mem" using /dev/rtc0 at Wed Apr  6 07:00:00 2022
````
If there are any services that currently run on the server you can specify the IP to have the script re-run the packet capture 3 times to make sure the network is not in use.
