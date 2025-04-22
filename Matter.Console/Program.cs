using Matter.Core;
using Matter.Core.Commissioning;

Console.WriteLine("dotnet-matter Console Application");
Console.WriteLine("Attempting to commission a Matter device");

Controller controller = new Controller();

//Commissioner commissioner = new Commissioner();

//commissioner.CommissionDevice(3840);

var commissioner = new NetworkCommissioner();

commissioner.CommissionDevice(3840);

Console.WriteLine("Commissioning done (timed out or worked)");

Console.ReadKey();
