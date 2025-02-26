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
                    return netInterface.GetPhysicalAddress().GetAddressBytes();
                }
            }

            throw new Exception($"MAC address for interface {interface_name} was not found.");
        }


        
        
    
    }
}