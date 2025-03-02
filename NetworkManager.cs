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

        //public enum IpVersion
        //{
            //IPv4,
            //IPv6
        //}
        
        public static byte[] GetTargetMac(string targetIp, string networkInterface) 
        {
            
            // get source IP and MAC
            byte[] sourceIp = GetSourceIPAddress(networkInterface);
            byte[] sourceMac = GetSourceMacAddress(networkInterface);

            Console.WriteLine("Source ipv6 IP: " + new IPAddress(sourceIp));

            IPAddress ipAddress = IPAddress.Parse(targetIp);
            byte[] targetIpBytes = ipAddress.GetAddressBytes();

            if(!IsIpv6Address(targetIp)) {
                if(!IsPrivateIp(targetIp))
                {
                    targetIpBytes = GetGatewayIP(networkInterface);
                }

                byte[] ethernetPacket = BuildArpRequest(sourceMac, sourceIp, targetIpBytes);
                
                // send ARP request packet -> get dest MAC
        
                return SendArpRequest(ethernetPacket, networkInterface, targetIpBytes);
            }
            else {
                byte[] ipv6Packet = BuildTargetMacIpv6Packet(sourceMac, sourceIp, targetIpBytes);
                return SendTargetMacIpv6Packet(ipv6Packet, networkInterface, targetIpBytes);
            }

                
        }
        
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
            return false;
        }

        private static bool IsPrivateIp(string ipAddress)
        {
            // get object of IP addr
            IPAddress ip;
            if (IPAddress.TryParse(ipAddress, out ip))
            {
                // get address bytes of IP
                byte[] addressBytes = ip.GetAddressBytes();

                // private A class range
                if (addressBytes[0] == 10)
                    return true;

                // private B class range
                if (addressBytes[0] == 172 && addressBytes[1] >= 16 && addressBytes[1] <= 31)
                    return true;

                // private C class range
                if (addressBytes[0] == 192 && addressBytes[1] == 168)
                    return true;

                // public IP
                return false;
            }
            else
            {
                Console.WriteLine("Error: Invalid IP address format.");
                Environment.Exit(1);
                return false;
            }
        }

        public static byte[] GetSourceMacAddress(string interface_name)
        {
            // find the network interface with the given name
            foreach (var netInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (netInterface.Name == interface_name || netInterface.Description.Contains(interface_name))
                {
                    byte[] macBytes = netInterface.GetPhysicalAddress().GetAddressBytes();
                    if(macBytes.Length == 6)
                    {
                        return macBytes;
                    }
                    
                }
            }
            Console.WriteLine($" Error: MAC address for interface {interface_name} was not found.");
            Environment.Exit(1);
            return null;
        }

        

        public static byte[] GetSourceIPAddress(string interface_name, bool isIpv6 = true)
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
                        if (isIpv6 && 
                            unicastAddress.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                        {
                            // Ignore loopback addresses
                            if (!IPAddress.IsLoopback(unicastAddress.Address))
                            {
                                return unicastAddress.Address.GetAddressBytes(); // Return the first valid IPv6 address found
                            }
                        }

                        // If the requested IP version is IPv4
                        if (!isIpv6 && 
                            unicastAddress.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            // Ignore loopback addresses
                            if (!IPAddress.IsLoopback(unicastAddress.Address))
                            {
                                return unicastAddress.Address.GetAddressBytes(); // Return the first valid IPv4 address found
                            }
                        }
                    }
                }
            }

            // If no valid IP address is found, throw an exception
            Console.WriteLine($"Error: address for interface {interface_name} was not found.");
            Environment.Exit(1);
            return null;
            
        }

        private static byte[] GetGatewayIP(string interfaceName) {
            
            // Find the specified network interface by name
            var networkInterface = NetworkInterface
                .GetAllNetworkInterfaces()
                .FirstOrDefault(nic => nic.Name == interfaceName);

            if (networkInterface == null)
            {
                Console.WriteLine($"Interface {networkInterface} not found.");
                return null;
            }

            // Get the gateway addresses for the interface
            var gatewayAddresses = networkInterface.GetIPProperties().GatewayAddresses;
            if (gatewayAddresses.Count == 1)
            {
                Console.WriteLine($"Gateway address: {gatewayAddresses[0].Address}");
                return gatewayAddresses[0].Address.GetAddressBytes();
            }
            Console.WriteLine("Error: Gateway address not found.");
            Environment.Exit(1);
            return null;
        }

        private static byte[] BuildTargetMacIpv6Packet(byte[] sourceMac, byte[] sourceIP, byte[] targetIP)
        {
            byte[] targetMac = new byte[] { 0x33, 0x33, 0xFF, targetIP[13], targetIP[14], targetIP[15] }; // IPv6 multicast MAC
            byte[] ndpPacket = new byte[86]; // Ethernet (14) + IPv6 (40) + ICMPv6 (24)

            // Ethernet header
            Array.Copy(targetMac, 0, ndpPacket, 0, 6); // Destination MAC
            Array.Copy(sourceMac, 0, ndpPacket, 6, 6); // Source MAC
            ndpPacket[12] = 0x86; // Ethernet type (IPv6)
            ndpPacket[13] = 0xDD;

            // IPv6 header
            ndpPacket[14] = 0x60; // Version, Traffic Class, Flow Label
            ndpPacket[15] = 0x00;
            ndpPacket[16] = 0x00;
            ndpPacket[17] = 0x00;
            ndpPacket[18] = 0x00; // Payload length (24 bytes for ICMPv6)
            ndpPacket[19] = 0x18;
            ndpPacket[20] = 0x3A; // Next header (ICMPv6)
            ndpPacket[21] = 0xFF; // Hop limit (255)
            Array.Copy(sourceIP, 0, ndpPacket, 22, 16); // Source IP
            byte[] multicastTarget = new byte[] { 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, targetIP[13], targetIP[14], targetIP[15] };
            Array.Copy(multicastTarget, 0, ndpPacket, 38, 16); // Destination IP

            // ICMPv6 Neighbor Solicitation header
            ndpPacket[54] = 0x87; // ICMPv6 type (Neighbor Solicitation)
            ndpPacket[55] = 0x00; // Code
            ndpPacket[56] = 0x00; // Checksum (to be computed later)
            ndpPacket[57] = 0x00;
            ndpPacket[58] = 0x00; // Reserved
            ndpPacket[59] = 0x00;
            ndpPacket[60] = 0x00;
            ndpPacket[61] = 0x00;
            Array.Copy(targetIP, 0, ndpPacket, 62, 16); // Target IP Address

            // Source Link-Layer Address Option
            ndpPacket[78] = 0x01; // Type: Source Link-Layer Address
            ndpPacket[79] = 0x01; // Length: 1 (8 bytes total)
            Array.Copy(sourceMac, 0, ndpPacket, 80, 6); // MAC Address

            return ndpPacket;

        }

        private static byte[] SendTargetMacIpv6Packet(byte[] ndpPacket, string networkInterface, byte[] targetIP)
        {
            var devices = CaptureDeviceList.Instance;
            if (devices == null || devices.Count == 0)
            {
                Console.WriteLine("Error: No devices found.");
                Environment.Exit(1);
                return null;
            }

            var device = devices.FirstOrDefault(d => d.Name == networkInterface);
            if (device == null)
            {
                Console.WriteLine("Error: No suitable device found.");
                Environment.Exit(1);
                return null;
            }

            device.Open();
            Console.WriteLine("Sending NDP Neighbor Solicitation...");
            device.SendPacket(ndpPacket);

            Console.WriteLine("Listening for Neighbor reply...");
            DateTime startTime = DateTime.Now;
            TimeSpan timeout = TimeSpan.FromSeconds(5);

            while (DateTime.Now - startTime < timeout)
            {
                PacketCapture rawPacket;
                if (device.GetNextPacket(out rawPacket) != GetPacketStatus.PacketRead)
                {
                    continue;
                }

                byte[] packetData = rawPacket.Data.ToArray();
                if (packetData.Length >= 78 && packetData[54] == 0x88) // ICMPv6 Neighbor Advertisement
                {
                    byte[] senderIp = new byte[16];
                    Array.Copy(packetData, 62, senderIp, 0, 16);
                    if (senderIp.SequenceEqual(targetIP))
                    {
                        byte[] senderMac = new byte[6];
                        Array.Copy(packetData, 78, senderMac, 0, 6);
                        Console.WriteLine($"Neighbor reply from {new IPAddress(senderIp)}: {BitConverter.ToString(senderMac)}");
                        device.Close();
                        return senderMac;
                    }
                }
            }

            device.Close();
            Console.WriteLine("Error: Neighbor reply not received within timeout.");
            Environment.Exit(1);
            return null;
        }
        

        // Constructs an ARP request packet to discover the MAC address of a target IP.
        // The request is encapsulated in an Ethernet frame and broadcasted on the network.

        private static byte[] BuildArpRequest(byte[] sourceMac, byte[] sourceIP, byte[] targetIP)
        {
            // broadcast MAC address
            byte[] targetMac = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

            byte[] arpPacket = new byte[42];

            // Ethernet header
            Array.Copy(targetMac, 0, arpPacket, 0, 6); // Destination MAC
            Array.Copy(sourceMac, 0, arpPacket, 6, 6); // Source MAC
            arpPacket[12] = 0x08; // Ethernet type (ARP)
            arpPacket[13] = 0x06;

            // ARP header
            arpPacket[14] = 0x00; // Hardware type (Ethernet)
            arpPacket[15] = 0x01;
            arpPacket[16] = 0x08; // Protocol type (IPv4)
            arpPacket[17] = 0x00;
            arpPacket[18] = 0x06; // Hardware size
            arpPacket[19] = 0x04; // Protocol size
            arpPacket[20] = 0x00; // Opcode (request)
            arpPacket[21] = 0x01;
            Array.Copy(sourceMac, 0, arpPacket, 22, 6); // Sender MAC address
            Array.Copy(sourceIP, 0, arpPacket, 28, 4); // Sender IP address
            Array.Copy(targetMac, 0, arpPacket, 32, 6); // Target MAC address
            Array.Copy(targetIP, 0, arpPacket, 38, 4); // Target IP address

            return arpPacket;
        }

        


        // Sends an ARP request packet and waits for a response containing the MAC address of the target IP.
        private static byte[] SendArpRequest(byte[] arpRequestPacket, string networkInterface, byte[] targetIP)
        {
            // get list of network devices
            var devices = CaptureDeviceList.Instance;

            if (devices == null || devices.Count == 0)
            {
                Console.WriteLine("Error: No devices found.");
                Environment.Exit(1);
                return null;
            }

            // find device based on interface name
            var device = devices.FirstOrDefault(d => d.Name == networkInterface);

            if (device == null)
            {
                Console.WriteLine("Error: No suitable device found.");
                Environment.Exit(1);
                return null;
            }

            device.Open();

            // send ARP request
            Console.WriteLine("Sending ARP request...");
            device.SendPacket(arpRequestPacket);

            Console.WriteLine("Listening for ARP replies...");

            // set timeout
            DateTime startTime = DateTime.Now;
            TimeSpan timeout = TimeSpan.FromSeconds(5);

            while (DateTime.Now - startTime < timeout)
            {
                PacketCapture rawPacket;
                // Read the next packet from the network device
                if (device.GetNextPacket(out rawPacket) != GetPacketStatus.PacketRead)
                {
                    continue;
                }

                byte[] packetData = rawPacket.Data.ToArray();

                // Check if the packet is an ARP reply
                if (packetData.Length >= 42 && packetData[12] == 0x08 && packetData[13] == 0x06 && packetData[20] == 0x00 && packetData[21] == 0x02)
                {
                    byte[] senderIp = new byte[4];
                    Array.Copy(packetData, 28, senderIp, 0, 4);

                    // Check if the ARP reply is from the target IP
                    if (senderIp.SequenceEqual(targetIP))
                    {
                        byte[] senderMac = new byte[6];
                        Array.Copy(packetData, 22, senderMac, 0, 6);
                        Console.WriteLine($"ARP Reply from {new IPAddress(senderIp)}: {BitConverter.ToString(senderMac)}");
                        device.Close();
                        return senderMac;
                    }
                }
            }

            device.Close();
            Console.WriteLine("Error: ARP Reply not received within timeout.");
            Environment.Exit(1);
            return null;
            
        }

       


    }


        


        
        
    
    
}