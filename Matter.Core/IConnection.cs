
namespace Matter.Core
{
    internal interface IConnection
    {
        Task<MessageFrame> ReadAsync();
        Task SendAsync(MessageFrame message);
    }
}
