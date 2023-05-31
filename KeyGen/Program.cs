using System.Security.Cryptography;

namespace KeyGen
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var rsaKey = RSA.Create();
            var privateKey = rsaKey.ExportRSAPrivateKey();
            File.WriteAllBytes("key", privateKey);
        }
    }
}