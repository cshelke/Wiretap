# Wiretap

============
Code Description:
============

The main objective of the project is to parse information hidden inside a network packet
where the packet can be obtained from an offline .pcap file. Just as the user can use softwares 
like Wireshark to get full details of the packet, the wiretap gives a simulation and feel of the 
software.

The main file associated with the project includes the wiretap.cpp

1. The user enters the .pcap file to be opened for parsing. Eg: wget.pcap
2. The packet in the file is then verified to be an ethernet packet or not.
3. A pcap_loop method is invoked which invokes a callback method where packet is counted.
4. Here since the user gets a packet he can extarct all the information required.
5. The various information extracted in the project includes:
    i.)       Ethernet (MAC) Source Address.
    ii.)      Ethernet (MAC) Destination Address.
    iii.)     Network Protocols.
    iv.)     Source IP Address.
    v.)      Destination IP Address.
    vi.)     Unique ARP Participants.
    vii.)    Transport Layer Protocols.
    viii.)    TCP Source and Destination Port Numbers.
    ix.)     TCP Flags.
    x.)      TCP Options.
    xi.)     UDP Source and Destination Port Numbers.
    xii.)     ICMP Types.
    xiii.)    ICMP Codes.

==============
Tasks Accomplished:
==============
1. Successful opening of the .pcap file
2. Verifying whether the packet is an ethernet packet or not.
3. Parsing the information in individual packet.

======
Compile:
======
Compile using th makefile provided.

Enter the command "make" to compile both the program. The output file out is created.

======
Execute:
======
To execute the wiretap.cpp two commands can be given depending upon the options the user wants
Following are some use cases.

I.) To execute server: 
./wiretap --open wget.pcap
./wiretap --help
./wiretap --help --open wget.pcap
./wiretap --open wget.pcap --help.

Note: Please store the pcap files in the location or directory where the wiretap.cpp and other files are
stored. Dont give a path for the .pcap file as an argument for '--open' command. For ex:

./wiretap --open /files/documents/wget.pcap ::-- Dont use

======
Interpret:
======
If the user gets the detailed information about all the attributes as stated in the code distribution 
then it can be concluded that the program has successfully implemented all the methods used
to parse an offline .pcap file.
