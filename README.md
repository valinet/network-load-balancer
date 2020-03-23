# Trivial Network Load Balancer
Trivial Network Load Balancer is a simple daemon for balancing traffic across multiple routes which lead to the Internet. By default, client Windows does not include any load balancing logic, so that when your computer has two or more NICs (network interface cards) connected to the Internet, Windows will always use only one of them for all connections. This is sub-optimal, as certain applications, like torrents and download accelerators (programs that download a file using multiple connections) could benefit if the connections were assigned to all the different interfaces. For example, with an optimal assignment and 2 NICs, potential transfer speed could be doubled.

My opinion is that omitting load balancing logic from the OS is intentional from Microsoft's part, so as not to piss off ISPs when people increase their connection speed without having to pay extra. This is further established by the fact that server versions of Windows include load balancing in the kernel. TNLB is a user space attempt as solving this issue.

TLNB injects itself into certain executables once launched. Then, each time the monitored application connects on a socket, the load balancer will be notified and will attempt to assign the connection to an appropiate NIC based on various criteria.

By default, each monitored application will have its connections assigned based on the "least used" policy (that is, the connection will be assigned to the NIC experiencing the least load). That seems to work well for most applications, although certain programs, like Internet Download Manager seem to favor more a round robin approach to balancing (RR is enabled by default for IDM).

## How to run?
I recommend compiling the application and adding a scheduled task that will run the it on each log on with highest privileges (in order to be able to monitor all processes and most importantly, change system routing preferences).

In order to successfully run the application, you have to compile the DLL (library project) for both 32-bit and 64-bit, so that it generates a DLL for each of the architectures.

For development, I used Visual Studio 2019 (cl 19.25.28610.4 for x86).

## How does it work?
The application uses Windows Management Instrumentation (WMI) to monitor network load and process creation. When a new process is created, the application checks the name of the process against a whitelist of apps to be injected (moduleNameIsMonitored in utility.cpp). If found on the list, the application loads an appropiate DLL into the process, which will send a message back to the application's window every time a "connect" call is made in the Winsock2 API. When the message is received, the application will adjust the Windows routing metrics so as to favour the route coresponding to the chosen NIC based on the criteria for that application, if specified, or the global, default criteria.

The application is able to inject same architecture processes, and also 32-bit processes when compiled as 64-bit (it maps the 32-bit kernel32.dll file into the memory and looks in the PE header for the address of the LoadLibraryW export). Also, connect call injection works on all architectures, with both the 32-bit and 64-bit versions of the Winsock2 library.
