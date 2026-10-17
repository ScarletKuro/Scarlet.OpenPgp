namespace Scarlet.OpenPgp.Hashing
{
    /// <summary>One-shot convenience over <see cref="HashContext"/> for data that is already in memory.</summary>
    internal static class OpenPgpHash
    {
        public static byte[] ComputeHash(HashAlgorithmId algorithm, byte[] data)
        {
            using HashContext context = HashContext.Create(algorithm);
            context.Update(data);
            return context.Finish();
        }
    }
}
