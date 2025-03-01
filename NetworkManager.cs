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

        public static byte[] GetTargetMac(string targetIp, string networkInterface) 
        {
            
            // get source IP and MAC
            byte[] sourceIp = GetSourceIPAddress(networkInterface);
            byte[] sourceMac = GetSourceMacAddress(networkInterface);

            IPAddress ipAddress = IPAddress.Parse(targetIp);
            byte[] targetIpBytes = ipAddress.GetAddressBytes();

            if(!IsPrivateIp(targetIp))
            {
                targetIpBytes = GetGatewayIP(networkInterface);
            }

            byte[] ethernetPacket = BuildArpRequest(sourceMac, sourceIp, targetIpBytes);
            
            // send ARP request packet -> get dest MAC
    
            return SendArpRequest(ethernetPacket, networkInterface, targetIpBytes);
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

        public static byte[] GetSourceIPAddress(string interface_name)
        {

            // find the network interface with the given name
            foreach (var netInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (netInterface.Name == interface_name || netInterface.Description.Contains(interface_name))
                {
                    // Iterate over all unicast addresses (addresses assigned to the interface)
                    foreach (var unicastAddress in netInterface.GetIPProperties().UnicastAddresses)
                    {
                        // Filter for IPv4 addresses only
                        if (unicastAddress.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            // Ignore loopback addresses (
                            if (!IPAddress.IsLoopback(unicastAddress.Address))
                            {
                                //string stringIp = unicastAddress.Address.GetAddressBytes().ToString();
                                //IPAddress ipAddress = IPAddress.Parse(stringIp);
                                //return ipAddress.GetAddressBytes(); // Return the first valid IPv4 address found
                                return unicastAddress.Address.GetAddressBytes();
                            }
                        }
                    }
                }
            }
        
            
            // If no valid IP address is found, throw an exception
            Console.WriteLine($"Error: IP address for interface {interface_name} was not found.");
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