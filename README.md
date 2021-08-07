# Detecting VPN Connection

## About
This script runs on a server and captures incoming traffic. The Round Trip Time is collected when the client connects to the server and then a probe is sent to determine a second Round Trip Time. If the Round Trip Times differ significally, then the IP address that connected will be classified as VPN, otherwise it will be classified as a Direct Connection. Then the data is stored in a Excel file. 

## Requirements

1. Must be a superuser running this program on a Linux machine. 
2. Must have python3 and pip
3. Install pyshark ``pip install pyshark``
4. Install xlsxwriter ``pip install xlsxwriter``
5. Install scapy ``pip install scapy``

## Acknowledgments
I wrote this script during the 2021 REU program at the University of Houston. During the program my advisor was Stephen Huang, the graduate students working on this project are Zechun Cao and Yuan Tian. The other REU student working alongside me is Ethan Endres.

The REU project is primarily sponsored by NSF under awards  CNS-1551221 and CCF-1950297. The UH College of Natural Sciences and Mathematics provides additional financial support.
