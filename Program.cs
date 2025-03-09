using System;
using CommandLine;



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

                // create OOP representation of the command line arguments
                scanParams = new ScanParams
                (
                    networkInterface: options.Interface,

                    // if udp/tcp ports null, create empty list
                    udpPorts: options.UdpPorts?.Split(',').ToList() ?? new List<string>(),
                    tcpPorts: options.TcpPorts?.Split(',').ToList() ?? new List<string>(),

                    targetIp: options.TargetIp
                    
                );

                
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
            
            
            
            scanParams.ScanTcpPorts();
            Console.WriteLine("Scanning UDP ports...");
            scanParams.ScanUdpPorts();
            
            

        }
    }
}
