using System;
using System.Net.NetworkInformation;
using System.Net;
using System.Net.Sockets;
using SharpPcap;
using SharpPcap.LibPcap;


namespace proj1
{
    static class NetworkManager
    {

        
        public static bool IsIpv6Address(string ipAddress)
        {
            if (IPAddress.TryParse(ipAddress, out IPAddress address))
            {
                if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    return false;
                }
                else if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    return true;
                }
            }
            Console.WriteLine("Error: Invalid IP address format.");
            Environment.Exit(1);
            return false;   
        }

        

        public static byte[] GetSourceIpAddress(string interface_name, ScanParams.IpVersion ipAddressFormat)
        {
            // Find the network interface with the given name
            foreach (var netInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (netInterface.Name == interface_name || netInterface.Description.Contains(interface_name))
                {
                    // Iterate over all unicast addresses (addresses assigned to the interface)
                    foreach (var unicastAddress in netInterface.GetIPProperties().UnicastAddresses)
                    {
                        // If the requested IP version is IPv6
                        if (ipAddressFormat ==  ScanParams.IpVersion.IPv6 && 
                            unicastAddress.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                        {
                            return unicastAddress.Address.GetAddressBytes(); // Return the first valid IPv6 address found
                        }

                        // If the requested IP version is IPv4
                        if (ipAddressFormat ==  ScanParams.IpVersion.IPv4 && 
                            unicastAddress.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            return unicastAddress.Address.GetAddressBytes(); // Return the first valid IPv4 address found
                        }
                    }
                }
            }

            // If no valid IP address is found, throw an exception
            Console.WriteLine($"Error: address for interface {interface_name} was not found.");
            Environment.Exit(1);
            return null;
            
        }

        
        public static byte[] BuildUpdPacket(int srcPort, int destPort)
        {
            byte[] packet = new byte[8]; // UDP header (8B)

            // source port
            packet[0] = (byte)(srcPort >> 8);
            packet[1] = (byte)(srcPort & 0xFF);

            // destination port
            packet[2] = (byte)(destPort >> 8);
            packet[3] = (byte)(destPort & 0xFF);

            // packet length (8B header + 0B payload)
            packet[4] = 0x00;
            packet[5] = 0x08;

            // checksum
            packet[6] = 0x00;
            packet[7] = 0x00;

            return packet;
        }

        public static List<string> ResolveIpsFromDomain(string domain)
        {
            
            try
            {
                var addresses = Dns.GetHostAddresses(domain);
                if (addresses.Length > 0)
                {
                    return addresses.Select(address => address.ToString()).ToList();
                }
                else
                {
                    throw new Exception();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: Unable to resolve domain name.");
                Environment.Exit(1);
                return null;
            }
        }



        public static byte[] SetPortBytes(ushort port) {
            byte[] portBytes = BitConverter.GetBytes(port);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(portBytes);
            }
            return portBytes;
        }

        public static ushort CalculateChecksum(byte[] data)
        {
            uint sum = 0;
            for (int i = 0; i < data.Length; i += 2)
            {
                ushort word = (ushort)((data[i] << 8) + (i + 1 < data.Length ? data[i + 1] : 0));
                sum += word;
                if ((sum & 0xFFFF0000) != 0)
                {
                    sum = (sum & 0xFFFF) + (sum >> 16);
                }
            }
            return (ushort)~sum;
        }    


    }
}