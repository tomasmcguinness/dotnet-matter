using Matter.Core;
using Matter.Core.Fabrics;

Console.WriteLine("dotnet-matter >> Console Application");


IFabricStorageProvider fabricStorageProvider = new FabricDiskStorage("H:\\fabrics");
IMatterController controller = new MatterController(fabricStorageProvider);

await controller.InitAsync();

//Console.WriteLine("Attempting to commission a Matter device");

//ICommissioner commissioner = await controller.CreateCommissionerAsync();

//await commissioner.CommissionNodeAsync(3840);

//Console.WriteLine("Commissioning done (timed out or worked)");