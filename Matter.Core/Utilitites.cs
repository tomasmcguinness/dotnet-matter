namespace Matter.Core
{
    public static class Extensions
    {
        public static byte[] ToByteArray(this string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        const long EPOCH_S = 946684800;

        public static uint ToEpochTime(this DateTimeOffset dt)
        {
            return (uint)(dt.ToUnixTimeSeconds() - EPOCH_S);
        }
    }
}
