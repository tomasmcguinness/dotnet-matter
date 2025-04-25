namespace Matter.Core.Sessions
{
    internal interface ISession
    {
        MessageExchange CreateExchange();

        byte[] Encode(MessageFrame message);

        MessageFrame Decode(byte[] payload);

        Task<byte[]> ReadAsync();

        Task SendAsync(byte[] payload);
    }
}
