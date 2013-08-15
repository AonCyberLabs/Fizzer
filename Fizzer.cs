using System;
using System.Collections.Generic;
using System.Collections;
using System.Text;
using System.Text.RegularExpressions;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace FixFuzzer
{
    class Program
    {
        public static String logFile = String.Empty;

        //Starting orderId.
        public static int startorderId = 1000;

        /*Error message thrown by server indicating Sequence number is off.  
         * Include text up until correct sequence number given by server.  This is used to split the error message string and update  */
        public static string sequenceError = @"Serious Error:  Message sequence number: \d+ is less than expected sequence number:";

        static void Main(string[] args)
        {
            //args[0]=TargetIP, args[1]=TargetPort, args[2]=SenderCompId, args[3]=InputFile, args[4] = starting sequence number, args[5]= logFile (optional)
            if (args.Length < 5)
            {
                Console.WriteLine();
                Console.WriteLine("=== Fizz - Simple Fuzzer for FIX Protocol Messages ===");
                Console.WriteLine();
                Console.WriteLine("Usage:  Fizzer.exe <host> <port> <sender-comp-id> <input file> <sequence start> [csv log file]");
                Console.WriteLine();
                return;
            }

            if (args.Length > 5)
            {
                logFile = args[5];
                FileStream fs = File.Create(logFile);
                fs.Close();

                // Make log file headers
                logMessage("TimeStamp", "Message Sent", "Message Received", "Time Elapsed");
            }

            String beginString = "8=FIX";

            //Read sample file
            byte[] messagesBytes = File.ReadAllBytes(args[3]);
            string input = System.Text.Encoding.UTF8.GetString(messagesBytes);

            //Parse out messages
            string[] messages = Regex.Split(input, "[^0-9]" + beginString);

            // This will hold the logon message
            string logonMessage = String.Empty;

            //For Each Message
            int sequence = int.Parse(args[4]);
            int ordId = startorderId;

            foreach (string msg in messages)
            {
                if (msg.Length <= 0)
                {
                    // Invalid data, skip it
                }
                else if (!msg.Contains(getSoh() + "49=" + args[2] + getSoh()))
                {
                    // Wrong Sender CompId
                    Console.WriteLine("[WARNING] - Skipping Message (Wrong Sender or Invalid Message) : " + args[2]);
                }
                else
                {
                    // Use this message...
                    // Add back the beginString
                    String testMessage = beginString + msg;
                    Console.WriteLine("[INFO] - Got Message: " + testMessage);

                    // Split message on the separator (SOH)
                    string[] parts = Regex.Split(testMessage, getSoh());


                    //For Each Fix Tag -- Fuzz
                    foreach (string part in parts)
                    {
                        if (part.Length > 0)
                        {
                            // Loop through each tag/name value

                            //First see if it is a logon message (if we don't already have one)
                            if (String.IsNullOrEmpty(logonMessage) && part.Equals("35=A")) // LOGON MESSAGE
                            {
                                logonMessage = msg;
                                Console.WriteLine("[INFO] - Logon Message Detected (skipping)");
                                break;
                            }
                            else if (part.Equals("35=0") || part.Equals("35=A")){
                                Console.WriteLine("[INFO] - Logon or Heartbeat Message Detected (skipping)");
                                break;
                            }
                            else if (part.StartsWith("8=") || part.StartsWith("9=") || part.StartsWith("35=") || part.StartsWith("34=") || part.StartsWith("10="))
                            {
                                //Don't fuzz these tags
                            }
                            else if (String.IsNullOrEmpty(logonMessage))
                            {
                                Console.WriteLine("[WARNING] - Skipping Message (No Logon Request Found)");
                            }
                            else
                            {
                                                              
                                //Fuzz it -- Send every Fuzz String
                                foreach (string fuzz in getFuzzList())
                                {
                                    String newPart = Regex.Replace(part, "=.*", "=" + fuzz);
                                    String fuzzMessage = testMessage.Replace(part, newPart);
                                    Console.WriteLine("[INFO] - Sending Fuzzed Tag: " + newPart);
                                    sendFuzzMessage(args[0], int.Parse(args[1]), ref sequence, ref ordId, logonMessage, fuzzMessage, testMessage);
                                    Console.WriteLine();

                                    //Deliberately pause for 500ms as a courtesy to the server
                                    System.Threading.Thread.Sleep(500);
                                }
                          
                                
                            }
                        }
                     
                    }

                    
                }
            }
        }


        static void sendData(TcpClient client, NetworkStream stream, String data, out String response)
        {
            // Translate the message into Bytes and send
            Byte[] dataBytes = System.Text.Encoding.ASCII.GetBytes(data);

            // Send the message to the connected TcpServer. 
            stream.Write(dataBytes, 0, dataBytes.Length);

            //System.Threading.Thread.Sleep(1000);
            // Buffer to store the response bytes.
            dataBytes = new Byte[256];

            // String to store the response ASCII representation.
            String responseData = String.Empty;
            stream.ReadTimeout = 30 * 1000;
            // Read the first batch of the TcpServer response bytes.
            try
            {

                Int32 bytes = stream.Read(dataBytes, 0, dataBytes.Length);
                response = System.Text.Encoding.ASCII.GetString(dataBytes, 0, bytes);
            }
            catch (Exception e)
            {
                Console.WriteLine("[ERROR] - " + e.Message);
                response = String.Empty;
            }
            
        }

        static void logMessage(String strTestTime, String strTestRequest, String strTestResponse, String strResponseTime)
        {
            if (!String.IsNullOrEmpty(logFile))
            {
                StreamWriter swLogger = File.AppendText(logFile);
                swLogger.WriteLine(quoteForCsv(strTestTime) + "," + quoteForCsv(strTestRequest) + "," + quoteForCsv(strTestResponse) + "," + quoteForCsv(strResponseTime));
                swLogger.Flush();
                swLogger.Close();
            }
        }

        static string quoteForCsv(String str)
        {
            str = str.Replace("\"", "\"\"");
            return "\"" + str + "\"";
        }

        static void sendFuzzMessage(String host, int port, ref int sequence, ref int ordId, String logonMsg, String fuzzMsg, String Original)
        {

            TcpClient client = null; 
            NetworkStream stream = null;
            String fuzzResponse = string.Empty;


            #region Login
           // Connect to the server
           client = getSocketConn(host, port);
           stream = client.GetStream();
                
           //try logging on for a maximum of 5 attempts
            for (int i = 0; i < 5; ++i)
            {
            //Update Time and Sequence number in Logon Message
                logonMsg = updateTimeSequenceChecksum(logonMsg, sequence, ordId);
                Console.WriteLine("[INFO] - Sending Logon Message: " + logonMsg);
                sendData(client, stream, logonMsg, out fuzzResponse);
                Console.WriteLine("[INFO] - Got Logon Response: " + fuzzResponse);

                //Look for error with sequence number.  If found, update sequence and restart logon process
                if (Regex.IsMatch(fuzzResponse, sequenceError))
                {
                    sequence = Convert.ToInt32((Regex.Split(Regex.Split(fuzzResponse, sequenceError)[1], getSoh()))[0]);
                    Console.WriteLine("[INFO] - Sequence Number Mismatch.  Changing Sequence To: " + sequence);
                }
                //Look for Empty Response
                else if (String.IsNullOrEmpty(fuzzResponse) || Regex.IsMatch(fuzzResponse, @"Empty String"))
                {
                    //Reset Socket
                    stream.Close();
                    client.Close();
                    client = getSocketConn(host, port);
                    stream = client.GetStream();
                    System.Threading.Thread.Sleep(500);
                }
                else
                {
                    //Logged on
                    //Look for Logon Message Here if Desired
                    break;
                }
            }

            #endregion

            //Send Fuzz Message
            fuzzMsg = updateTimeSequenceChecksum(fuzzMsg, ++sequence, ++ordId);
            Console.WriteLine("[INFO] - Sending Fuzz Message: " + fuzzMsg);
            DateTime testTime = DateTime.Now;
            sendData(client, stream, fuzzMsg, out fuzzResponse);
            TimeSpan responseTime = DateTime.Now - testTime;
            logMessage(testTime.ToString("yyyyMMdd-H:mm:ss.fff"), fuzzMsg, fuzzResponse, responseTime.Milliseconds.ToString());

            //In the event of Blank String, Make Logs Easier to Parse
            if (String.IsNullOrEmpty(fuzzResponse))
            {
                fuzzResponse = "NULL OR EMPTY STRING RETURNED";
            }
            //Look for Resend Request (35=2).  Most servers will hang until a proper message is accepted.  Try sending the original message
            else if(Regex.IsMatch(fuzzResponse, getSoh() + "35=2" + getSoh()))
            {
                Console.WriteLine("[INFO] - Got Resend Request: " + fuzzResponse);
                
                //try sending the orginal message to reset the system
                fuzzMsg = updateTimeSequenceChecksum(Original, sequence, ordId);
                Console.WriteLine("[INFO] - Sending Clean Message: " + fuzzMsg);
                testTime = DateTime.Now;
                sendData(client, stream, fuzzMsg, out fuzzResponse);
                responseTime = DateTime.Now - testTime;
                logMessage(testTime.ToString("yyyyMMdd-H:mm:ss.fff"), "reset::" + fuzzMsg, fuzzResponse, responseTime.Milliseconds.ToString());

                //account for response sequence number
                ++sequence;
            }
            else{
                //account for response sequence number
                ++sequence;
            }
            Console.WriteLine("[INFO] - Got Fuzz Response: " + fuzzResponse);

            // Close everything.
            stream.Close();
            client.Close();
        }

      
        static ArrayList getFuzzList()
        {
            ArrayList fuzzList = new ArrayList();


            // Control Characters
            fuzzList.Add("te'st");
            fuzzList.Add("te|st");
            fuzzList.Add("te../..st");
            fuzzList.Add("te..\\..st");

            // Long data
            
            fuzzList.Add(new String('A', 8));
            fuzzList.Add(new String('A', 16));
            fuzzList.Add(new String('A', 32));
            fuzzList.Add(new String('A', 64));
            fuzzList.Add(new String('A', 128));
            fuzzList.Add(new String('A', 256));
            fuzzList.Add(new String('A', 512));
            fuzzList.Add(new String('A', 1024));
            fuzzList.Add(new String('A', 2048));
            fuzzList.Add(new String('A', 4096));
            fuzzList.Add(new String('A', 8192));
            fuzzList.Add(new String('A', 16384));
            

            // Integer Boundaries
            fuzzList.Add("-129");
            fuzzList.Add("-128");
            fuzzList.Add("127");
            fuzzList.Add("128");
            fuzzList.Add("255");
            fuzzList.Add("256");
            fuzzList.Add("-32769");
            fuzzList.Add("-32768");
            fuzzList.Add("32767");
            fuzzList.Add("32768");
            fuzzList.Add("65535");
            fuzzList.Add("65536");
            fuzzList.Add("-2147483649");
            fuzzList.Add("-2147483648");
            fuzzList.Add("2147483647");
            fuzzList.Add("2147483648");
            fuzzList.Add("4294967295");
            fuzzList.Add("4294967296");
            fuzzList.Add("-9223372036854775809");
            fuzzList.Add("-9223372036854775808");
            fuzzList.Add("9223372036854775807");
            fuzzList.Add("9223372036854775808");
            fuzzList.Add("18446744073709551615");
            fuzzList.Add("1152921504606846976");


            // Format Strings
            fuzzList.Add("%x");
            fuzzList.Add("%n");
            fuzzList.Add("%s");
            fuzzList.Add("%s%p%x%d");
            fuzzList.Add("%p%p%p%p");
            fuzzList.Add("%x%x%x%x");
            fuzzList.Add("%d%d%d%d");
            fuzzList.Add("%s%s%s%s");
            fuzzList.Add("%99999999999s");
            fuzzList.Add("%08x");
            fuzzList.Add("%20d");
            fuzzList.Add("%20n");
            fuzzList.Add("%20x");
            fuzzList.Add("%20s");


            
            fuzzList.Add("%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d");
            fuzzList.Add("%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i");
            fuzzList.Add("%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o%o");
            fuzzList.Add("%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u");
            fuzzList.Add("%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x");
            fuzzList.Add("%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X");
            fuzzList.Add("%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a%a");
            fuzzList.Add("%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A");
            fuzzList.Add("%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e%e");
            fuzzList.Add("%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E%E");
            fuzzList.Add("%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f%f");
            fuzzList.Add("%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F%F");
            fuzzList.Add("%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g%g");
            fuzzList.Add("%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G%G");
            fuzzList.Add("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s");
            fuzzList.Add("%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p");
            fuzzList.Add("%#0123456x%08x%x%s%p%d%n%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%08x%%");
            fuzzList.Add("XXXXX.%p");
            //fuzzList.Add("XXXXX" + fuzzList.Add(new String('.%p', 80); " perl -e 'print ".%p" x 80'`);
            //fuzzList.Add("`perl -e 'print \".%p\" x 80'`%n);
            fuzzList.Add("%08x.%08x.%08x.%08x.%08x\\n");
            fuzzList.Add("XXX0_%08x.%08x.%08x.%08x.%08x\\n");
            fuzzList.Add("%.16705u%2\\$hn");
            fuzzList.Add("\\x10\\x01\\x48\\x08_%08x.%08x.%08x.%08x.%08x|%s|");
            fuzzList.Add("AAAAA%c");
            fuzzList.Add("AAAAA%d");
            fuzzList.Add("AAAAA%e");
            fuzzList.Add("AAAAA%f");
            fuzzList.Add("AAAAA%I");
            fuzzList.Add("AAAAA%o");
            fuzzList.Add("AAAAA%p");
            fuzzList.Add("AAAAA%s");
            fuzzList.Add("AAAAA%x");
            fuzzList.Add("AAAAA%n");
            fuzzList.Add("ppppp%c");
            fuzzList.Add("ppppp%d");
            fuzzList.Add("ppppp%e");
            fuzzList.Add("ppppp%f");
            fuzzList.Add("ppppp%I");
            fuzzList.Add("ppppp%o");
            fuzzList.Add("ppppp%p");
            fuzzList.Add("ppppp%s");
            fuzzList.Add("ppppp%x");
            fuzzList.Add("ppppp%n");
            fuzzList.Add("%@");
            fuzzList.Add("%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@");
            

            //Executable Commands
            fuzzList.Add("test'; waitfor delay('0:0:30')--");
            fuzzList.Add("&&sleep 20;");
            fuzzList.Add("te<script>alert('fix_fuzz')</script>");


            return fuzzList;
        }

        static String updateTimeSequenceChecksum(String fixMessage, int seqNum, int ordId)
        {
            // Update Timestamp
            fixMessage = Regex.Replace(fixMessage, getSoh() + "52=.*?" + getSoh(), getSoh() + "52=" + DateTime.Now.ToString("yyyyMMdd-H:mm:ss.fff") + getSoh());

            // Update Sequence Number
            fixMessage = Regex.Replace(fixMessage, getSoh() + "34=.*?" + getSoh(), getSoh() + "34=" + seqNum + getSoh());

            //update orderID
            fixMessage = Regex.Replace(fixMessage, getSoh() + "11=.*?" + getSoh(), getSoh() + "11=" + ordId.ToString() + "/" + DateTime.Now.ToString("yyyy-MM-dd-HH:mm") + getSoh());
            
            // Update Length
            int length = fixMessage.IndexOf(getSoh() + "10=") - fixMessage.IndexOf(getSoh() + "35=");

            fixMessage = Regex.Replace(fixMessage, getSoh() + "9=.*?" + getSoh(), getSoh() + "9=" + length + getSoh());

            // Remove checksum to calculate new one
            String messageNoChecksum = Regex.Replace(fixMessage, getSoh() + "10=.*", getSoh());

            char[] inputChars = messageNoChecksum.ToCharArray();
            int checkSum = 0;

            foreach (char aChar in inputChars)
            {
                checkSum += (int)aChar;
            }

            // Update Checksum
            fixMessage = Regex.Replace(fixMessage, getSoh() + "10=.*", getSoh() + "10=" + (checkSum % 256).ToString("000") + getSoh());
            return fixMessage;
        }

        public static string getSoh()
        {
            return System.Text.Encoding.UTF8.GetString(new byte[] { 01 });
        }

        static public TcpClient getSocketConn(String host, int port)
        {
            TcpClient client = new TcpClient();
            
            //Try 5 connection attempts
            for(int i = 0; i < 5; i++)
            {
                try
                {
                    client.Connect(host, port);
                    return client;
                }
                catch (System.Net.Sockets.SocketException SE)
                {
                    Console.WriteLine("[ERROR] - Cannot not connect to host. Press any key to re-try.");
                    Console.WriteLine(SE.Message);
                    System.Console.ReadLine();
                }
            }

            throw new ApplicationException("[ERROR] - Maximum number of connection attempts has exceeded.");
        }

    }
}
