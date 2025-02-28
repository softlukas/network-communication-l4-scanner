using System;
using CommandLine;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Net;
using System.Diagnostics;
using PacketDotNet;



namespace proj1
{
    class Program
    {
        static void Main(string[] args)
        {
            ScanParams scanParams = null;
            Parser.Default.ParseArguments<ArgsOptions>(args)
            .WithParsed(options =>
            {
                if (string.IsNullOrEmpty(options.Interface) && string.IsNullOrEmpty(options.TargetIp))
                {
                    Console.WriteLine("Listing active interfaces...");
                    
                    return;
                }

                Console.WriteLine($"Interface: {options.Interface ?? "None"}");
                Console.WriteLine($"TCP Ports: {options.TcpPorts ?? "None"}");
                Console.WriteLine($"UDP Ports: {options.UdpPorts ?? "None"}");
                Console.WriteLine($"Timeout: {options.Timeout} ms");
                Console.WriteLine($"Target: {options.TargetIp ?? "None"}");
                
            
                // create OOP representation of the command line arguments
                scanParams = new ScanParams
                (
                    networkInterface: options.Interface,

                    // if udp/tcp ports null, create empty list
                    udpPorts: options.UdpPorts?.Split(',').ToList() ?? new List<string>(),
                    tcpPorts: options.TcpPorts?.Split(',').ToList() ?? new List<string>(),

                    targetIp: options.TargetIp,

                    sourceIp: NetworkManager.GetSourceIPAddress(options.Interface),
                    sourceMac: NetworkManager.GetSourceMacAddress(options.Interface),
                    targetMac: NetworkManager.GetTargetMac(options.TargetIp, options.Interface)
                );

                foreach(string item in scanParams.UdpPorts)
                {
                    Console.WriteLine(item);
                }
                
            })
            .WithNotParsed(errors =>
            {
                Console.WriteLine("Invalid arguments provided.");
                foreach (var error in errors)
                {
                    Console.WriteLine(error.ToString());
                }
            });

            Console.WriteLine(scanParams.ToString());

            scanParams.SendSynPacket();

        }
    }
}
