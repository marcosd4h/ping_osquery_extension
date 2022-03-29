# osquery_extension_ping
A small osquery extension to ping hosts through ICMP Echo Request/Reply packets

### Description
The project implements a new osquery virtual table called `ping`  that allows operators to ping hosts and receives a digested response.
The virtual table is delivered through an Osquery extension using the Osquery C++ SDK.

### Technical Overview
The extension was created around a custom-made library called `ping_helper_lib`. This library is in charge of abstracting the extension from the internals of the ICMP ping process while also providing a synchronous interface that can be used to execute the ICMP ping process.
The `ping_helper_lib` library uses [Boost.Asio](https://www.boost.org/doc/libs/1_78_0/doc/html/boost_asio.html)  library to send and receive the ICMP Echo Request/Reply packets asynchronously. The `ping_helper_lib` relies on C++ Lamba functions to handle the different scenarios found in the process of ICMP-pinging other hosts. The idea of abstracting the core functionality through a static library makes this logic easy to consume and unit test

### Result data
The following columns get returned once the `ping` table is queried:\
`host`: The target hostname\
`result`: Message describing the status of the request\
`ip_address`: Resolved target host IP address\
`sequence_number`: This number gets increased after each transmission\
`time_to_live`: This is is a value on an ICMP packet that prevents that packet from propagating back and forth between hosts ad infinitum\
`latency`: It is the Round trip time in milliseconds between the sent ICMP echo request and the received ICMP echo reply packets

### Usage overview
The new ping table can be exercised through regular osquery SQL queries like the ones below: \
Pinging localhost: `SELECT latency FROM ping WHERE host = ‘127.0.0.1’;`\
Pinging a domain: `SELECT * FROM ping WHERE host = ‘www.google.com’;` \
Pinging multiple hosts: `select * from ping WHERE (host = "127.0.0.1" OR host = "google.com");` 

### Building the extension
In order to build the extension binaries and unit tests, the entire `extension_ping` directory has to be copied or soft-linked as a directory inside of the `external` directory on Osquery code.  Then, the `externals` target has to be used as detailed [here](https://osquery.readthedocs.io/en/stable/development/osquery-sdk/#building-external-extensions).

### TODO
[ ] Improve Cmake file to get the extension built on Linux\
[ ] Apply Osquery clang formatting style to ping helper library\
[ ] Add extra logging on both library and extension code\
[ ] Add code comments inline with expected Osquery doc format\
[ ] Support passing a parameter to indicate the number of ICMP request packets (default is 1)
