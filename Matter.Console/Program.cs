using Matter.Core;
using Matter.Core.Commissioning;
using Matter.Core.Fabrics;

Console.WriteLine("dotnet-matter >> Console Application");

IFabricStorageProvider fabricStorageProvider = new FabricDiskStorage("H:\\fabrics");
IMatterController controller = new MatterController(fabricStorageProvider);

await controller.InitAsync();

//Console.WriteLine("Attempting to commission a Matter device");

var manualPairingCode = args[0];

var commissioningPayload = CommissioningPayloadHelper.ParseManualSetupCode(manualPairingCode);

ICommissioner commissioner = await controller.CreateCommissionerAsync();
await commissioner.CommissionNodeAsync(commissioningPayload);

//Console.WriteLine("Commissioning done (timed out or worked)");

await controller.RunAsync();
