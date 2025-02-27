using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;



namespace proj1
{
    static class NetworkManager
    {
        
        public static bool IsPrivateIp(string ipAddress)
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
                throw new ArgumentException("Invalid IP address format.");
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

            throw new Exception($"MAC address for interface {interface_name} was not found.");
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
            throw new Exception("IP address not found.");
        }
        

        // Constructs an ARP request packet to discover the MAC address of a target IP.
        // The request is encapsulated in an Ethernet frame and broadcasted on the network.

        public static Packet BuildArpRequest(byte[] sourceMac, byte[] sourceIP, byte[] targetIP)
        {
            // Create an Ethernet packet with:
            // - Destination MAC: Broadcast address (FF:FF:FF:FF:FF:FF)
            // - Source MAC: Provided source MAC address
            // - Ethernet Type: ARP (Address Resolution Protocol)
            
            // set destination MAC to broadcast
            byte[] destMac = new byte[6];
            destMac = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
            
            // create Ethernet packet
            var ethernetPacket = new EthernetPacket(
                new PhysicalAddress(sourceMac),
                new PhysicalAddress(destMac),   //broadcast                                    
                EthernetType.Arp);

            // Create an ARP request packet with:
            
            var arpPacket = new ArpPacket(
                ArpOperation.Request,             // ARP request operation
                new PhysicalAddress(destMac),     // braodcast
                new IPAddress(targetIP),          
                new PhysicalAddress(sourceMac),   
                new IPAddress(sourceIP));         

            // Attach the ARP packet as the payload of the Ethernet frame.
            ethernetPacket.PayloadPacket = arpPacket;

            // Return the complete Ethernet frame containing the ARP request.
            byte[] rawBytes = ethernetPacket.Bytes;
            return ethernetPacket;
        }

        // Sends an ARP request packet and waits for a response containing the MAC address of the target IP.
        public static byte[] SendArpRequest(Packet arpRequestPacket, string interfaceName, byte[] targetIP)
        {
            // get list of network devices
            var devices = CaptureDeviceList.Instance;

            if (devices == null || devices.Count == 0)
            {
                Console.WriteLine("No devices found.");
                return null;
            }

            // find device baased on interface name
            var device = devices.FirstOrDefault(d => d.Name == interfaceName);

            if (device == null)
            {
                Console.WriteLine("No suitable device found.");
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
                    Console.WriteLine("citam packet");
                    continue;
                }
                
                var linkLayerType = device.LinkType;

                
                Packet packet = Packet.ParsePacket(linkLayerType, rawPacket.Data.ToArray());
                
                var ethPacket = packet.Extract<EthernetPacket>();

                if (ethPacket == null || ethPacket.Type != EthernetType.Arp)
                {
                    continue;
                }
                
                var arpPacket = packet.Extract<ArpPacket>();
                if (arpPacket == null || arpPacket.Operation != ArpOperation.Response)
                {
                    continue;
                }
                
                // Check if the ARP reply is from the target IP
                if (arpPacket.SenderProtocolAddress.Equals(new IPAddress(targetIP)))
                {
                    Console.WriteLine($"ARP Reply from {arpPacket.SenderProtocolAddress}: {arpPacket.SenderHardwareAddress}");
                    device.Close();
                    return arpPacket.SenderHardwareAddress.GetAddressBytes();
                }
            }

            device.Close();
            throw new TimeoutException("ARP Reply not received within timeout.");
            
            
        }

       


    }


        


        
        
    
    
}