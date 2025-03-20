using Matter.Core;
using Matter.Core.Commissioning;

Console.WriteLine("Hello, World!");

Controller controller = new Controller();

Commissioner commissioner = new Commissioner();

commissioner.StartBluetoothDiscovery();

Console.ReadKey();
