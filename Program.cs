using System;
using CommandLine;
using System.Net.NetworkInformation;



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
                // if interface or target is not set
                if (string.IsNullOrEmpty(options.Interface) || string.IsNullOrEmpty(options.TargetIp)) {
                    Console.WriteLine("Listing active interfaces...");

                    var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                    foreach (var ni in interfaces)
                    {
                        Console.WriteLine($"Name: {ni.Name}, Description: {ni.Description}, Status: {ni.OperationalStatus}");
                    }
                    Environment.Exit(1);
                }

                // create OOP representation of the command line arguments
                scanParams = new ScanParams
                (
                    networkInterface: options.Interface,

                    // if udp/tcp ports null, create empty list
                    udpPorts: options.UdpPorts?.Split(',').ToList() ?? new List<string>(),
                    tcpPorts: options.TcpPorts?.Split(',').ToList() ?? new List<string>(),

                    targetIp: options.TargetIp,
                    timeout: options.Timeout
                    
                );

                
            })
            .WithNotParsed(errors =>
            {
                Console.WriteLine("Error");   
            });

            Console.WriteLine(scanParams.ToString());
            
            
            
            scanParams.ScanTcpPorts();
            Console.WriteLine("Scanning UDP ports...");
            scanParams.ScanUdpPorts();
            
            

        }
    }
}
