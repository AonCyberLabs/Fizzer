Fizzer - Fix Fuzzing Framework
===========================================
Authors: 

Brian Holyfield - Gotham Digital Science 
Michael Hanchak - Gotham Digital Science 

www.gdssecurity.com
labs@gdssecurity.com

===========================================
Usage:

    Fizzer.exe <host> <port> <sender-comp-id> <input file> <sequence start> [csv log file]

Input file should be a TCPDump or Wireshark capture of a legitimate fix conversation in raw format.  Messages will be extracted and used as the base for fuzzing.  The last login request sent to the Fix Receiver will also be extracted.  Messages where the SenderCompId does not match the value from the command line, Logon, and Heartbeat messages will all be ignored.  In addition, the following fields are not fuzzed by default in this release: BeginString(8), BodyLength(9), MsgType(35), MsgSeqNum(34), and CheckSum(10)   

===========================================
License:
 
Fizzer is released under the Apache License, version 2.0 (Apache-2.0)
https://opensource.org/licenses/Apache-2.0

===========================================
