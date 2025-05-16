namespace Matter.Core.Fabrics
{
    public interface IFabricStorageProvider
    {
        bool DoesFabricExist(string fabricName);

        Task<Fabric> LoadFabricAsync(string fabricName);

        Task SaveFabricAsync(Fabric fabric);
    }
}
