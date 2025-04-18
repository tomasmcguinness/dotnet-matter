namespace Matter.Core.Sessions
{
    internal interface ISession
    {
        MessageExchange CreateExchange();

        Task<MessageFrame> ReadAsync();

        Task SendAsync(MessageFrame message);
    }
}
