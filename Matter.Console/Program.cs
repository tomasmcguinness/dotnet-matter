using Matter.Core;
using Matter.Core.Commissioning;

Console.WriteLine("Hello, World!");

Controller controller = new Controller();

Commissioner commissioner = new Commissioner();

commissioner.CommissionDevice(3840);

Console.WriteLine("Commissioning successful");

Console.ReadKey();
