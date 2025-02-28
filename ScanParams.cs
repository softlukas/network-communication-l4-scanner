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
    class ScanParams
    {
        public string? NetworkInterface { get; private set; }
        public List<string> UdpPorts { get; private set; }
        public List<string> TcpPorts { get; private set; }
        public string? TargetIp { get; private set; }
        public byte[] SourceIp { get; private set; }
        public byte[] SourceMac { get; private set; }
        public byte[] TargetMac { get; private set; }

        private string stringSourceIp;
        private string stringTargetIp;
        private string stringSourceMac;
        private string stringTargetMac;

        public ScanParams(string? networkInterface, List<string> udpPorts, List<string> tcpPorts, 
        string? targetIp, byte[] sourceIp, byte[] sourceMac, byte[] targetMac)
        {
            NetworkInterface = networkInterface;
            UdpPorts = udpPorts;
            TcpPorts = tcpPorts;
            TargetIp = targetIp;
            SourceIp = sourceIp;
            SourceMac = sourceMac;
            TargetMac = targetMac;

            stringSourceMac = BitConverter.ToString(SourceMac);
            stringTargetMac = BitConverter.ToString(TargetMac);
            stringSourceIp = new IPAddress(SourceIp).ToString();
        }


        public override string ToString()
        {
            return $"Interface: {NetworkInterface ?? "None"}\n" +
                   $"UDP Ports: {string.Join(",", UdpPorts)}\n" +
                   $"TCP Ports: {string.Join(",", TcpPorts)}\n" +
                   $"Target IP: {TargetIp ?? "None"}\n" +
                   $"Source IP: {stringSourceIp}\n" +
                   $"Source MAC: {stringSourceMac}\n" +
                   $"Target MAC: {stringTargetMac}";
        }

        
        public void SendSynPacket() {
            // Find the specified network interface
            var devices = CaptureDeviceList.Instance;
            var device = devices.FirstOrDefault(d => d.Name == NetworkInterface);

            if (device == null)
            {
                Console.WriteLine($"Interface {NetworkInterface} not found.");
                return;
            }

            device.Open();

            // Create Ethernet frame
            var ethernetPacket = new EthernetPacket(
                PhysicalAddress.Parse(stringSourceMac),
                PhysicalAddress.Parse(stringTargetMac),
                EthernetType.IPv4
            );

            // Create IP header
            var ipPacket = new IPv4Packet(IPAddress.Parse(this.stringSourceIp), IPAddress.Parse(this.stringTargetIp))
            {
                Protocol = PacketDotNet.ProtocolType.Tcp,
                TimeToLive = 128
            };

            // Create TCP SYN packet
            var tcpPacket = new TcpPacket(12345, 80) // Source port, destination port
            {
                Flags = TcpFlags.SYN, 
                WindowSize = 8192
            };

            tcpPacket.ComputeChecksum(); // Compute the checksum

            
            ipPacket.PayloadPacket = tcpPacket;
            ethernetPacket.PayloadPacket = ipPacket;

            // Send the packet
            device.SendPacket(ethernetPacket);

            Console.WriteLine("SYN packet sent!");
            device.Close();
        }
        
    
    }
}