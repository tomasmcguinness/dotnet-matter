using Matter.Core;

Console.WriteLine("dotnet-matter >> Console Application");
Console.WriteLine("Attempting to commission a Matter device");

IMatterController controller = new MatterController();

var commissioner = await controller.CreateCommissionerAsync();

commissioner.CommissionDevice(3840);

Console.WriteLine("Commissioning done (timed out or worked)");