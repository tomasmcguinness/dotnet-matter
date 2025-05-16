using Matter.Core;
using Matter.Core.Fabrics;

Console.WriteLine("dotnet-matter >> Console Application");
Console.WriteLine("Attempting to commission a Matter device");

IFabricStorageProvider fabricStorageProvider = new FabricDiskStorage("H:\\fabrics");
IMatterController controller = new MatterController(fabricStorageProvider);

await controller.InitAsync();

//var commissioner = await controller.CreateCommissionerAsync();

//commissioner.CommissionDevice(3840);

//Console.WriteLine("Commissioning done (timed out or worked)");