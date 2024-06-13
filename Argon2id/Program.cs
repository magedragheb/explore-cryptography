using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Isopoh.Cryptography.Argon2;

var text = "y+('tMc%6R@Ub!V_`Nn;r/";
var salt = new byte[16];
RandomNumberGenerator.Fill(salt);
var config = new Argon2Config
{
    Salt = salt,
    Password = Encoding.UTF8.GetBytes(text)
};

Stopwatch sw = Stopwatch.StartNew();

var hash = Argon2.Hash(config);

sw.Stop();
Console.WriteLine(sw.ElapsedMilliseconds);
Console.WriteLine(hash);
sw.Restart();

Console.WriteLine(Argon2.Verify(hash, text));

sw.Stop();
Console.WriteLine(sw.ElapsedMilliseconds);